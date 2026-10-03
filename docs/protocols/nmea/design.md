# NMEA 0183（海用电子设备数据交换标准，National Marine Electronics Association 0183）设计契约

> 版本：v2.0.0（设计阶段）
> 日期：2026-09-02
> 状态：按《协议设计文档与用例文档需求文档 v1.3》完成层链迁移审计；cases 现有 **80 例（49 正 + 31 负）**，本轮仅改文档与 cases，不修改 Go/MCP 实现，也不宣称 suite 已复跑。
> 配套文件：`docs/protocols/nmea/testcase.md`、`trafficgen/test/protocol_pcap/cases/nmea.json`（80 例与 §9 ID 顺序对账）
> 规范基线与证据等级（逐项标注出处）：
> ① **NMEA 0183 v4.10 标准**（NMEA 发布；国际等同文本 IEC 61162-1）——句子结构（`$`+地址 5 字符+逗号字段+`*`+两位 hex 校验和+CRLF）、**标准句校验和可选**（"the checksum is optional for standard sentences"，§5.3.2 口径）与**专有句校验和强制**、**句子总长上限 82 字符（含 `$` 与 `<CR><LF>`）**、talker ID 表、七句型字段定义——标准文本为付费分发，条款号以②③公开文本交叉印证，未经印证的条款号一律不写（标注"付费规范，公开印证"）；
> ② **gpsd 项目《NMEA.txt》参考文档**（gitlab.com/gpsd/gpsd，开源，公开 NMEA 句型字段逐条清单）——GGA/RMC/GSA/GSV/VTG/GLL/ZDA 字段顺序与值域（出处写" gpsd NMEA.txt §<句型>"）；
> ③ **接收机手册公开示例**（u-blox NEO/GARMIN 手册、Wikipedia NMEA 0183 条目）——现网句子形态（时间 2 位小数、度分 3-4 位小数并存、GN 组合 talker 现网默认）交叉印证；
> ④ **本机实测**：tshark 3.6.14（Wireshark）`-G fields`/`-G protocols`——**无 NMEA dissector、无 `nmea.*` 字段**（`-G protocols | grep -ci nmea` = 0；含 "nmea" 的字段全部属于其他协议：`aprs.ct.nmea_src` 等），全部断言走 `tcp.payload`/`udp.payload` 整句 ASCII hex + frames offset 54/74（TCP）/42/62（UDP），**无 DecodeAs 依赖**（版本化实测基线，用例文档 §1）；
> ⑤ **公开资料 + 假设，实现阶段实证校准**：TCP/UDP 端口 10110（NMEA-0183-over-TCP 网关事实惯例，非 IANA 注册；gpsd 自有协议端口为 2947 不混用）、UDP 多播组 239.192.0.1:10110（AIS/NMEA 网关组播惯例）、串口服务器非默认端口 4001、校验和 hex 大写形态（gpsd/接收机默认大写；小写是否接受实现期校准）、度分小数位 2-4 位并存（fixture 钉死 3/4 位两种形态）——逐处标注。
> 修订记录：v2.0.0（2026-09-02）：按 v1.3 重写，取代 2026-08-20 v1.0.0 初稿（旧稿见 git 历史；旧稿 20 用例粗粒度、配置 v1.0 旧式扁平 JSON、负例三锚词候选列表、无逐字段表/无长度公式/无 hex 基线/无包数算式——23 findings 逐条落点见 §10）。

## 1. 范围、profile 和实现边界

本版定义 NMEA 0183 sentence（句子）在 **TCP（流式）与 UDP（数据报）双载体**上的明文生成与观察：`$` 起始、地址字段（talker ID 2 字符 + sentence type 3 字符）、逗号定界数据字段、可选 `*` 两位大写 hex XOR 校验和、CRLF 行结束；七标准句型（GGA/RMC/GSA/GSV/VTG/GLL/ZDA）+ `$P` 专有句；talker 变体（GP/GN/GL/II 代表 + 值域表）；度分/时间/日期/状态值域与边界；TCP 跨段四形态与多句粘连；UDP 单句/多句/多播；IPv4/IPv6；多会话与**并发会话**；FIN/RST/重连；pcap/NIC 双输出。

| profile（协议档案） | 承载 | 本版允许内容 | 不从 profile 推导 |
|---|---|---|---|
| `nmea_tcp_v1`（主 profile） | TCP 明文（端口 10110，⑤） | 七句型 + $P、talker 值域、CRLF 流式重组、校验和可选形态、FIN/RST/重连、多会话/并发 | 真实定位正确性、卫星真实存在、接收机真实状态 |
| `nmea_udp_v1` | UDP 明文（端口 10110；多播 239.192.0.1:10110 一例，⑤） | 同句型集；数据报边界保留（单句/多句/多播） | 跨数据报拼接、广播形态（显式不产生，§8） |
| `nmea_ipv6_v1` | 同上，仅外层 IPv6 | TCP/UDP 句子字节与 v4 完全一致 | 从 IPv4 fixture（固定样本）推导 IPv6 地址 |

**层链迁移例外（当前能力缺口）**：正例 41/43 仍保留 TCP 与 UDP 层并存、由会话 `transport` 选择载体的历史形状；这与严格的单一 `[ip,carrier,nmea]` C2 形状冲突。按当前代码能力保留作为迁移缺口登记，不将其伪造为已完成的可运行混合载体；后续应拆成独立载体用例或由 registry/validator 明确定义多载体形状。

**显式边界（"不实现、不臆造、不进正例"）**：① **`!` 起始 AIS 封装句**（`!AIVDM/!AIVDO` 族，IEC 61162-2/NMEA 0183 v4.x 六位 ASCII 封装）——非本版句型集，进负例（§7 `start_bang`）；② **NMEA 4.1 tag block**（`[s:…,c:…]` 句前标签块）不产生；③ **GSV signal ID 字段**（v4.10+ 第 5 字段）、**RMC/GSA/VTG/GLL 之外的 v4.1 扩展字段**不产生（fixture 钉死经典字段数）；④ 支持句型集 = 7 标准句型 + `$P`，**其余标准句型（DBT/VHW/HDT/MWV/AAM…数十个）为显式不产生边界**，负例注入用未定义码 `XYZ`（不逐个枚举）；⑤ **NMEA 2000**（CAN 总线，完全不同协议）不实现；⑥ 广播 UDP 目的形态不产生（单播 fixture + 多播一例，§8）。

**实现边界**：本轮只核对层链契约与 cases 形状，不据此证明 registry、planner、validator、translate、suite 或 NIC 已完成。80 个 cases 均为语义用例；负例 `nmea_tcp_wf_carrier_layer_missing` 专门登记缺承载层错误形状。

**输出契约（pcap/NIC 双输出）**：本契约的用例同时服务于 pcap（抓包文件）与 port_group/NIC（网卡）两种输出路径——两路径共用同一份 cases JSON、同一 tshark 字段/帧字节断言，不设仅单路径可用的断言。逐项：① pcap = 离线文件，断言走 `tcp.payload`/`udp.payload` 整句 hex + offset 54/74/42/62 frames + `tcp.len`/`tcp.stream`/`udp.length`/`udp.stream`；② NIC = port_group 网卡输出（实测口 enp135s0f0np0），经 tcpdump 捕获（`nic_capture` 用例级开关）后以同一 tshark 断言集核验——**网卡 checksum offload 仅影响 IP/TCP/UDP 校验和字段，NMEA 句内 XOR 校验和是应用层 ASCII 文本，不受 offload 影响**（旧稿 §6 一句话口径升级为契约段，全用例覆盖，不设独立"NIC 专用断言"）；③ TCP 跨段句（正例 31-36）两路径均按 `tcp.stream` 重组后断言整句（NIC 抓包分段与 pcap 一致）；④ 多会话/并发（44/45）在两路径以 `tcp.stream`/`udp.stream` distinct 区分；⑤ IPv6（39/41）两路径 offset 74/62 一致（fixture 无 VLAN，无偏移漂移）；⑥ 多句粘连段（30）两路径同为单段多句、段内 CRLF 计数断言一致（与 64-cwmp/66-doh/67-onvif/68-hl7/70-megaco/65-bacnet/75-stratum 同形）。本批没有独立命名的 pcap/NIC 一致性专项例；契约段定义了两条输出路径的共同断言，实际双路径一致性仍登记为 G-NMEA-2，不能由现有 80 例静态形状宣称完成。

## 2. 协议栈、端口和固定偏移

推荐层链 TCP 为 `[tcp, nmea]`、UDP 为 `[udp, nmea]`（引擎自动补 `ip`；需要显式地址族时写 `[ip, tcp, nmea]` 或 IPv6 等价链）。NMEA 句子是 TCP 字节流/UDP 数据报 payload 的**整体内容**——无长度前缀、无记录头，句子边界只由 CRLF 决定（TCP）或数据报边界承载完整句（UDP）。**多载体声明**：在已登记的 cases 形状中，NMEA 为终结层，会话级 `transport` 表达每个会话所用载体；正例 41/43 保留为**C2 迁移缺口**（层链同时出现 tcp/udp，严格单一承载层尚未满足），不宣称当前 planner/validator 已完成混合传输输出。

端口：**TCP/UDP 默认 10110**（⑤ NMEA-over-TCP 网关事实惯例，非 IANA 注册——端口不是协议识别证据）。本版 fixture 统一 `dst_port=10110`；**非默认端口显式声明即合法通道**（正例 42 `nmea_port_nondefault` 用 4001，串口服务器常见，⑤），句子字节与基线完全一致；未显式声明的非 10110 端口拒绝（负例 78）。**无 DecodeAs 依赖声明**：本机无 NMEA dissector（§1④ 实测），全部断言走 `tcp.payload`/`udp.payload` 与端口无关——"非默认端口需 DecodeAs"判例（hl7#27/bacnet#46）在本协议不适用（彼处有 dissector 依赖端口自动解码，此处无 dissector 可言，与 75-stratum §2 同口径）。

固定偏移：无 VLAN（虚拟局域网）、IP options（IP 选项）与 TCP options 时，**每句首字节（`$`=`0x24`）起点：TCP/IPv4 offset（偏移）54（Ethernet 14 + IPv4 20 + TCP 20）、TCP/IPv6 offset 74（14 + IPv6 40 + TCP 20）、UDP/IPv4 offset 42（14 + 20 + UDP 8）、UDP/IPv6 offset 62（14 + 40 + UDP 8）**。**TCP 分段边界不是句子边界**：一个段可含半句、整句或多句粘连（句界由 CRLF 定界）；UDP 数据报边界即句集边界（一报文一句或多句，不跨报文）。

## 3. 线格式编码（逐项标注出处）

### 3.1 句子抽象结构与长度公式（①②）

```text
sentence  = "$" address "," field[1] "," … "," field[n] ["*" hh] CR LF
address   = talker_id(2 ASCII) + sentence_type(3 ASCII)
hh        = XOR(address "," field[1] "," … "," field[n]) 的两位大写 hex   ; $ 与 * 不参加 XOR
$P 专有句 = "$" "P" mfr_id(3 ASCII) payload ["*" hh] CR LF               ; 校验和强制（①）
```

- **长度公式**：`L = 1($)+5(address)+Σ(len(field_i)+1)+3(*+hh)+2(CRLF)`；无校验和形态 `L = 1+5+Σ(len+1)+2`。**句长上限 82 字符（含 `$` 与 CRLF，①）**——`L ≤ 82` 是 validator 硬校验（负例 71 用 83B 注入）；无下限（最短空句 `$GPZDA,,,,,,*hh` 形态合法，fixture 不产生空句、声明见 §8）。
- **字段定界**：逗号分隔；空字段 = 相邻逗号间零字符（**占位不可删**——删逗号造成后续字段左移，校验按位置逐字段进行）；小数点 `.` 为数值内字符。
- **字符集**：可打印 ASCII（0x20–0x7E）；CR=`0x0D`、LF=`0x0A` 仅出现于行尾（字段内出现控制字符为线格式错）。
- **CRLF 组帧**：行结束恒 `0D 0A`；仅 LF（`0A`）或仅 CR 均非法（负例 52/`lf_only`；裸结束无 CRLF 为负例 51）。

### 3.2 地址字段：talker ID 与 sentence type（①③）

**talker ID 值域表**（两 ASCII 大写字母；fixture 用前四个，其余为值域声明，代表值策略 §8）：

| talker | 含义 | fixture |
|---|---|---|
| `GP` | GPS 单星座 | 基线（全部句型默认） |
| `GN` | 组合 GNSS（**现网多星座接收机默认**，③） | 正例 23 |
| `GL` | GLONASS | 正例 24 |
| `II` | 集成仪表（Raymarine 惯例） | 正例 25 |
| `GA`/`GB`/`GQ`/`GI` | Galileo / BeiDou / QZSS / NavIC | `GQ` 正例 49；其余为值域声明 |
| `BD` | 北斗（国产接收机惯例，③） | 值域声明 |
| `AI`/`EC`/`HC`/`WI`/`CD`/`SD`/`VD` | AIS / 电子海图 / 磁罗经 / 气象 / DSC / 深度 / 速度 | 值域声明 |

表内 talker × 支持句型**任意组合合法**（GSV/GLL 等无 talker 约束）；非法面：表外 talker（负例 57 `ZZ`）、`P` 被当标准 talker（`$PGA…`，5 字符地址误用——`P` 只能出现在 `$P`+3 字符厂商 ID 专有形态，负例 59）。**sentence type 值域 = 支持集 {GGA,RMC,GSA,GSV,VTG,GLL,ZDA}**；表外 formatter 进负例 58（注入 `XYZ`；其余真实标准句型按 §1 边界④ 不逐个设例）。

### 3.3 校验和规则（①⑤，N-11 口径落字）

| 项 | 规则 | 出处 |
|---|---|---|
| 输入域 | `$` 后第一个字节至 `*` 前最后一个字节的全部 ASCII 字节（含地址与全部逗号）——**`$` 与 `*` 本身排除** | ① |
| 算法 | 8 位逐字节 XOR | ① |
| 编码 | 恰两位十六进制字符；**大写形态 fixture 钉死**（gpsd/接收机默认，⑤）；小写形态本版**不产生**（接受与否实现期校准，§8 声明） | ①⑤ |
| **标准句（七句型）：可选** | "the checksum is optional for standard sentences"（①§5.3.2 口径，付费规范、gpsd 与公开综述印证）——**无 `*hh` 直接 CRLF 结尾是合法形态**（正例 22 `nmea_checksum_omitted_standard`）；旧稿"缺 `*xx` 即负例"口径据此废除 | ①② |
| **专有句（$P）：强制** | 专有句校验和强制（①）——`$P` 句无 `*hh` 进负例 74 | ① |
| 宽度 | `*` 后必须恰两位 hex：一位/三位均非法（负例 73） | ① |
| 本版生成口径 | `checksum:true`（缺省）生成 `*hh`；`checksum:false` 仅允许标准句型（$P 拒绝）；**`wire_fault:"checksum_mismatch"` 注入 XOR 不一致句**：负例形态（validator 拒绝，72）与**观测模式**（引擎按事件声明生成并原样输出、expect 不含 error——正例 17，两态同源、同一注入入口，N-21 口径：引擎是"生成并原样输出"，不是"转发"） | 设计决策 |

### 3.4 七句型逐字段规格（字段号 = 地址后数据字段序号；②③ 逐条 + ① 句型定义）

**GGA（GPS 定位数据，14 个数据字段）**：

| # | 字段 | 类型/宽度 | 值域 | 空字段形态 |
|---:|---|---|---|---|
| 1 | UTC 时间 | `hhmmss.ss` 固定 9 字符 | hh 00-23 / mm 00-59 / ss 00-59 / 小数 2 位（fixture 钉死 `.00`） | 可空 |
| 2 | 纬度 | `ddmm.mmmm` 变长 8-11 字符 | dd 00-90（dd=90 时分必须 00.0000）/ 分 00-59.9999（小数 2-4 位，⑤） | 可空（无定位） |
| 3 | 纬半球 | 1 字符 | `N`/`S` | 可空 |
| 4 | 经度 | `dddmm.mmmm` 变长 9-12 字符 | ddd 000-180（180 时分必须 00.0000）/ 分同上 | 可空 |
| 5 | 经半球 | 1 字符 | `E`/`W` | 可空 |
| 6 | 定位质量 | 1 数字 | 0=无效/1=GPS SPS/2=DGPS/3=PPS/4=RTK 固定/5=RTK 浮动/6=DR 估计/7=手动/8=模拟 | 可空 |
| 7 | 使用卫星数 | 2 数字 | 00-99（fixture 08） | 可空 |
| 8 | HDOP | `x.x` 变长 | 数值 | 可空 |
| 9 | 海拔 | `x.x` 变长 | 数值（M 单位基准） | 可空 |
| 10 | 海拔单位 | 1 字符 | `M` | 可空 |
| 11 | 大地水准面差 | `x.x` 变长 | 数值 | 可空 |
| 12 | 单位 | 1 字符 | `M` | 可空 |
| 13 | DGPS 年龄 | `x.x` 变长 | 秒数 | **常空**（基线空，DGPS 形态 `1.0`，正例 3） |
| 14 | 差分站 ID | 4 数字 | 0000-1023 | **常空**（DGPS 形态 `0001`，正例 3） |

fixture：`$GPGGA,123519.00,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*69`（70B 含 CRLF）；无定位形态 `$GPGGA,123519.00,,,,,0,,,,M,,M,,*45`（37B，字段 2-5/7-9/13-14 全空、质量 0、单位 M 占位 f10/f12——正例 4）；DGPS 形态 `…E,2,…,1.0,0001*44`（77B，正例 3）；质量枚举帧 1/2/4（正例 5）。

**RMC（推荐最小 GNSS 数据，12 字段）**：

| # | 字段 | 类型 | 值域 | 空字段形态 |
|---:|---|---|---|---|
| 1 | UTC 时间 | hhmmss.ss | 同 GGA#1 | 可空 |
| 2 | 状态 | 1 字符 | `A`=有效 / `V`=警告（接收机警告，**句子存在≠定位有效**） | 可空 |
| 3-6 | 纬/半球/经/半球 | 同 GGA#2-5 | 同上 | V 状态时空（正例 7） |
| 7 | 地速 SOG | `x.x` | 节 | V 状态时空 |
| 8 | 地理航向 COG | `ddd.d` | 000.0-359.9 | V 状态时空 |
| 9 | 日期 | `ddmmyy` 固定 6 字符 | dd 01-31 / mm 01-12 / yy 00-99 | 可空 |
| 10 | 磁偏角 | `x.x` | 数值 | 可空 |
| 11 | 磁偏角方向 | 1 字符 | `E`/`W` | 可空 |
| 12 | 模式 | 1 字符 | `A`=自主/`D`=差分/`E`=估算/`N`=无效（NMEA 2.3+，③） | 可空 |

fixture：`$GPRMC,123519.00,A,4807.038,N,01131.000,E,022.4,084.4,230394,003.1,W,A*29`（75B）；V 形态 `$GPRMC,123519.00,V,,,,,,,230394,,,N*7F`（40B，字段 3-8/10-11 空 + 模式 N——正例 7 第 2 帧）。

**GSA（卫星工作状态与 DOP，17 字段）**：

| # | 字段 | 类型 | 值域 | 空字段形态 |
|---:|---|---|---|---|
| 1 | 模式 | 1 字符 | `M`=手动强制 2D/3D / `A`=自动 | 不可空 |
| 2 | 定位维度 | 1 数字 | 1=无 / 2=2D / 3=3D | 不可空 |
| 3-14 | 卫星 ID 槽 ×12 | 2 数字/槽 | 01-99（每槽可空，**槽位不可压缩**——空槽保留逗号） | 稀疏空（正例 11）/满槽（正例 8） |
| 15 | PDOP | x.x | 数值 | 可空 |
| 16 | HDOP | x.x | 数值 | 可空 |
| 17 | VDOP | x.x | 数值（**2D 定位时空**——无高度解，正例 10） | 可空 |

fixture：满槽 `$GPGSA,A,3,04,05,06,09,12,17,19,24,25,29,31,32,2.5,1.3,2.0*3F`（63B，12 星满槽=卫星 ID 集全集，正例 8）；手动模式 `M,3,…,32,2.5,1.3,2.0*33`（63B，正例 9 帧 2）；2D `$GPGSA,A,2,04,05,,09,,,,,,,,,2.5,1.3,*10`（42B，VDOP 空，正例 10）；稀疏 5 槽 `…,04,05,,09,12,,,,,,,,2.5,1.3,2.0*3E`（47B，正例 11）。v4.10 第 18 字段 system ID 不产生（§1 边界③）。

**GSV（可见卫星信息，变长字段 = 3 头字段 + 4×N 卫星组）**：

| # | 字段 | 类型 | 值域 |
|---:|---|---|---|
| 1 | 总消息数 | 1 数字 | 1-9（fixture 1 与 3） |
| 2 | 消息序号 | 1 数字 | 1-字段1（**句间关联标识**：同序列消息数恒同、序号 1..N 连续——负例 75 校验） |
| 3 | 可见卫星总数 | 2 数字 | 00-99 |
| 4+4k | 卫星组 ×N（N≤4） | 每组 4 字段 | ID 01-99 / 仰角 `00`-`90`（2 数字）/ 方位角 `000`-`359`（3 数字）/ SNR `00`-`99` 或**空**（未锁定，正例 14） |

fixture：单消息 `$GPGSV,1,1,02,04,45,190,47,29,80,270,39*79`（44B，正例 12）；三消息序列 `3,1,11`/`3,2,11`/`3,3,11`（4+4+3 星=11 恰闭合（卫星集除 32 外），校验和 `*76`/`*70`/`*40`，各 70/70/57B，正例 13）；SNR 空形态 `$GPGSV,1,1,01,04,45,190,*45`（29B，仰角/方位在场、SNR 空，正例 14）。v4.10 signal ID 字段不产生（§1 边界③）。

**VTG（航向与地速，9 字段）**：真航向 `ddd.d`、`T`、磁航向 `ddd.d`（可空，正例 fixture 空）、`M`、地速节 `x.x`、`N`、地速 km/h `x.x`、`K`、模式 1 字符（`A`/`D`/`E`/`N`，NMEA 2.3+）。fixture：`$GPVTG,084.4,T,,M,022.4,N,041.4,K,A*00`（40B——校验和 `00` 恰为数值 0 合法形态）。

**GLL（地理位置，7 字段）**：纬/半球/经/半球（同 GGA）+ UTC 时间 + 状态 `A`/`V` + 模式（`A`/`D`/`E`，可空）。fixture：`$GPGLL,4807.038,N,01131.000,E,123519.00,A,A*66`（48B）。

**ZDA（时间与日期，6 字段）**：UTC `hhmmss.ss` + 日 `01`-`31` + 月 `01`-`12` + 年 4 数字 + 本地时区小时 **带符号 2 位**（`+00`..`+13`/`-13`..`-00`，⑤形态：前导 `+`/`-`）+ 本地时区分 `00`-`59`。fixture：`$GPZDA,123519.00,23,03,1994,+08,00*4F`（39B）；负时区 `$GPZDA,123519.00,23,03,1994,-05,30*47`（正例 18 帧 2）。

**$P 专有句**：`$P` + 厂商 ID 3 字符（A-Z）+ payload（逗号定界，**opaque 不透明**——按原始字节保留与观察，不臆造语义）+ `*hh`（强制）+ CRLF。fixture：`$PGRME,15.0,M,20.0,M,25.0,M*1F`（32B，Garmin 估计误差句公开示例，③）。厂商 ID 表不维护（`GRM` 等 3 字符域交 validator 字符集校验）。

### 3.5 每句型行长公式与 fixture 实测长度

| 句型 | 公式（`6 + Σ(len(f_i)+1) + 3 + 2`；Σ 为数据字段） | fixture 实测长 |
|---|---|---:|
| GGA | `6 + Σ(14 个数据字段长+1) + 5` | 70（基线）/ 77（DGPS 全字段）/ 37（无定位） |
| RMC | `6 + Σ(12 字段+1) + 5` | 75 / 40（V） |
| GSA | `6 + 2+2 + Σ(12 槽+1) + 5+5+5 + 5`（VDOP 空时末项 `0+1`） | 63（满槽 12 星）/ 42（2D VDOP 空）/ 47（稀疏） |
| GSV | `6 + 2+2+3 + Σ(4N 字段+1) + 5` | 44（2 星）/ 70/70/57（3 消息）/ 29（SNR 空） |
| VTG | `6 + Σ(9 字段+1) + 5` | 40 |
| GLL | `6 + Σ(7 字段+1) + 5` | 48 |
| ZDA | `6 + Σ(6 字段+1) + 5` | 39 |
| $P | `6 + Σ(payload 段+1) + 5`（强制校验和） | 32 / **82**（上界句 `$PXYZ,P×71*77`，正例 36） |
| 无校验和标准句 | `6 + Σ(len+1) + 2` | 67（GGA 基线去 `*69`） |

（fixture 逐句 hex 与 XOR 复算值见用例文档 §3 字节基线表；全部长度经脚本实测核对。）

### 3.6 `!` AIS 起始符显式排除（N-10）

NMEA 0183 v4.x 起定义 `!` 起始的 AIS 封装句（`!AIVDM`/`!AIVDO` 等，六位 ASCII 载荷、**校验和强制**、属 IEC 61162-2 载荷族）——**本版不实现、不产生**：`$` 是本版唯一合法起始符（§3.1），`!` 起始行进负例 56（锚 `start`）；`!AIVDM` 句内结构不做任何解析声明。tag block（§1 边界②）同理不产生（负例不设，§8 声明）。

## 4. 业务场景分析（现网典型场景与五层覆盖）

**定性声明**：本引擎对 NMEA 采用**声明式脚本化回放**——配置是剧本（sessions[]/events[] 逐条声明），引擎是回放者，按序产出句子帧；"事件驱动"一词不用于定性整体行为，仅用于两处反应性成分：①**连接边界**（事件序列中源端口切换触发新 TCP 连接）；②**自动应答性成分不存在**（NMEA 是纯单向通知流，引擎不补任何响应帧——与 cwmp/doh 等请求/响应协议不同，此处显式声明为"无"）。

| 现网场景 | 交互形态 | 驱动顺序 | 对应用例 |
|---|---|---|---|
| ① GPS 接收机持续推送（最常见：串口服务器/TCP 网关把 NMEA 流透明送出） | 单向流：GGA/RMC 交替周期输出 | 设备驱动全程（events[] 事件序列） | 1、2、6、20 |
| ② 多星座接收机（现网默认 GN talker） | 同①，talker=GN | 设备驱动 | 23（GN）/24（GL） |
| ③ 无定位告警（隧道/室内：接收机仍在输出但无解） | GGA 质量 0 空字段 / RMC 状态 V | 设备驱动 | 4、7 |
| ④ 卫星状态巡检（GSA DOP + GSV 可见星多句） | GSA 周期 + GSV 1-3 句序列 | 设备驱动，GSV 序列按 1..N | 8-14 |
| ⑤ 航行数据面板（VTG/GLL/ZDA） | 周期输出 | 设备驱动 | 15-18 |
| ⑥ 厂商扩展（Garmin 等 $P 句混入标准流） | 标准句 + $P 混流 | 设备驱动 | 19 |
| ⑦ AIS/GPS 网关多设备并发（N 台设备同时推送） | 多会话按序 或 `concurrent:true` 交错 | 各自驱动，状态互不串 | 44、45 |
| ⑧ 传感器断流重连（GNSS 重启/串口服务器掉电） | 流中断（RST 或 FIN）→ 新连接句子流重启 | 设备侧事件编排 | 46、47 |
| ⑨ UDP 网关（单播/组播分发） | 数据报承载句集 | 设备驱动 | 37-40 |

**五层覆盖逐层结论**：功能层——七句型 + $P 每型至少一例（字段级拆分：GGA 4 例/RMC 2/GSA 4/GSV 3/VTG/GLL/ZDA 各 1）、校验和三形态（复算/大写/省略）、talker 4 例、负例 31 行逐故障；性能层——82B 句长上界（正例 36 + 负例 71 相邻 83）、TCP 跨段四形态 + 多句粘连 + 30 句打包跨 MSS（30-36）、UDP 多句单报文（38）；数据场景层——度分值域（0/满度/59.9999/南西半球，26-29）、时间/日期/状态/模式/质量枚举（5/7/17/18 + 负例 17/18/19/20/21）、空字段形态（3/4/7/10/11/14）、GSA 槽稀疏/满、GSV SNR 空；地址与流层——TCP/UDP × v4/v6 四组合（1/37/39/41）、多播一例（40）、非默认端口（42）、多载体 fixture（43）、多会话（44）、**并发会话（45）**、RST/重连（46/47）；**流关联显式不适用**：NMEA 是单向传感器数据流，无控制面/数据面分离、无副连接派生（全部信息在同一流内）；**多流（一个会话内部并发流）显式不适用**：单连接串行输出；业务层——接收机推送/多星座/无定位/巡检/多设备网关/断流重连/UDP 分发均为现网日常。**事务与状态机：显式不适用**——NMEA 单向通知流无请求/响应、无事务、无应用层会话状态（唯一句间关联 = GSV 序列的 total/msg_num，§5）。

## 5. 消息/事务模型与状态机（单向流声明，N-15）

**事务模型：无**——NMEA 0183 是单向（设备→采集端）通知流：无请求/响应配对、无关联标识事务、无应用层状态机（接收端对每句独立解析）。**唯一的句间关联 = GSV 多句序列**：`total_msgs`（字段 1）与 `msg_num`（字段 2）——同序列 total 恒同、msg_num 从 1 连续递增至 total；序号跳变/超总数为关联错（负例 75，锚 `sequence`）。事件编排（events[]）按序回放句子，GSV 序列由事件序自然保证（validator 校验序列字段自洽）。

**连接生命周期（TCP）**：`ConnectPending`（三次握手完成→首段句子）→ `Streaming`（句子按序产出；段界任意：单句单段/多句粘连/跨段切句）→ `Terminating`（FIN 四步挥手，全部正例默认 `terminates=true`）或 `Aborted`（RST 单帧中断，正例 46：`tcp.flags.reset==1`、RST 后无任何句子帧、无挥手）。**重连口径（N-8）**：连接关闭（FIN 或 RST）即流终止——重连 = 新 TCP 连接（新四元组/新源端口）+ 句子流从头回放（事件序列重启），**无会话恢复语义**（NMEA 无应用层状态可恢复；GSV 序列若跨连接中断则新连接重新从 msg 1 起）；正例 47 断言新 `tcp.stream`、第二流首句重启。**保活口径（N-8）**：无应用层 keepalive 帧（NMEA 无心跳句型）；TCP 层 keepalive 探测本版不产生——长连接活性由句子周期输出体现（事件序列即节拍），不设 keepalive 正例亦不进负例。**UDP 无连接口径**：无握手/挥手/RST/重连语义——正例不携带 `has_handshake`/`terminates`（恒 false 不写入 expect）；每数据报 = 1 包。

**多会话与并发（N-1）**：`sessions[]` 多会话形状按序整块回放（先跑完会话 1 全流程再跑会话 2，第二会话包号起点 = 前会话总包数 + 1）；`concurrent: true` 是多设备交错回放的配置边界。**多载体（N-23）**：正例 41/43 记录 TCP 与 UDP 共存配置及其顺序反转边界；它们不宣称当前实现已完成混合传输输出。

**自动派生规则**（引擎自动补出的帧，逐条列出）：① TCP 三次握手与 FIN 挥手由 tcp 层自动补（连接边界反应性成分：源端口切换触发新连接）；② RST 由会话级 `termination:"rst"` 声明显式触发（非自动）；③ XOR 校验和按事件字段渲染后的句内字节自动计算（`checksum:true` 时）；④ 除上述外不自动生成任何协议帧（无自动应答、无自动重传、无自动句子轮换——句子序列完全由 events[] 声明）。

## 6. 配置 typedef（JSON 形状示例，非 Go 代码；N-2 对齐 harness 形态）

```json
{
  "layers": [{"tcp": {}}, {"nmea": {}}],
  "src_ip": "192.0.2.69", "dst_ip": "198.51.100.69",
  "src_port": 40069, "dst_port": 10110,
  "nmea": {
    "sessions": [
      {
        "src_port": 40069, "dst_port": 10110,
        "events": [
          {"kind": "sentence", "talker": "GP", "type": "GGA", "checksum": true,
           "fields": ["123519.00", "4807.038", "N", "01131.000", "E", "1", "08",
                      "0.9", "545.4", "M", "46.9", "M", "", ""]},
          {"kind": "sentence", "talker": "GP", "type": "RMC", "checksum": true,
           "fields": ["123519.00", "A", "4807.038", "N", "01131.000", "E", "022.4",
                      "084.4", "230394", "003.1", "W", "A"]}
        ]
      },
      {
        "src_port": 40070, "dst_port": 10110, "transport": "udp",
        "events": [
          {"kind": "sentence", "talker": "GN", "type": "GGA", "checksum": true, "fields": ["…同上…"]}
        ]
      }
    ],
    "pack": true,
    "wire_fault": ""
  }
}
```

**配置形状说明**：正文中的 JSON 示例统一采用 `layers` 层链与终结层 `nmea` 子映射；“cases JSON 占位/harness 形态”仅指字段结构，不表示注册占位。`sessions[]` = 统一术语的**事件编排会话**（每个自带四元组与事件序列；多会话展开按序整块回放，第二会话包号起点 = 前会话总包数 + 1；`concurrent: true` 并发交错回放——正例 45，N-1）；`events[]` = 会话的**事件序列**，元素为一笔"产出一句话"事件：`kind:"sentence"` + `talker`（值域 §3.2 表）+ `type`（支持集）+ `checksum`（true=计算 `*hh`；false=无校验和，仅标准句型）+ `fields`（按句型字段序的字符串数组，**空字段保留为空串**——validator 逐字段校验数量/值域/位置）；会话级 `transport:"udp"` 覆盖层链载体（多载体 fixture，N-23）；`termination:"rst"` 会话级声明（正例 46）；`pack:true` 相邻句子合并为单段（缺省 false = 每句一段；组帧用例配合 `tcp.mss` 与事件级 `split_hint`（可选字节偏移注入口，驱动 §3 四种跨段切位））；`wire_fault` 仅负例注入口，**31 值枚举与 §7 表、用例文档 §5 表三方同序一一映射**（N-4/N-5；旧稿 8 值枚举与"坏 JSON"外类故障废除）：`missing_dollar`、`missing_crlf`、`lf_only`、`truncated_tcp`、`udp_truncated`、`udp_cross_datagram`、`start_bang`、`unknown_talker`、`unknown_type`、`talker_p_standard`、`field_count_short`、`field_count_extra`、`lat_over`、`lon_over`、`minutes_over`、`direction_char`、`time_out_of_range`、`date_out_of_range`、`status_char`、`gsa_mode_char`、`gsa_fix_type`、`sentence_length`、`checksum_mismatch`、`checksum_hex_width`、`proprietary_no_checksum`、`gsv_seq_correlation`、`carrier_layer_missing`、`carrier_conflict`、`port_undeclared`、`address_family_mismatch`、`propagation`——每值钉死单一注入形态（§7 表逐行）与单一主锚词。**配置到帧的完整路径**：配置 → validator（层链/载体一致/端口声明/talker 值域/type 支持集/字段数量与逐字段值域/句子长度 ≤82/校验和规则/GSV 序列自洽/wire_fault 仅注入不落线）→ planner（events[] 展开为句子序列，逐句按 §3.5 公式计算长度与 XOR）→ worker（TCP：按 pack/split_hint/mss 切段；UDP：按 pack 组报文，报文边界不切句）→ writer（PCAP/NIC 双输出，§1 契约）。

## 7. 错误处理（负例锚词表；N-4/N-5/N-6 原子拆分）

以下输入必须由 planner/validator 拒绝并传播为 task error（任务错误），不得产出成功 PCAP、`completed/0 packet` 或只剩 TCP/UDP 外壳的假成功。**单一注入纪律（N-4）：一行一例，钉死该行注入的单一 `wire_fault`/配置变异；主锚词为钉死的单一字面值**（不再是候选列表），与用例文档 §5 表一一对应（31 行同序，`wire_fault` 31 值三方映射见 §6）：

| # | 负例 ID | 类别 | 故障输入（单一注入） | 主锚词 `error_contains` |
|---:|---|---|---|---|
| 50 | `nmea_neg_missing_dollar` | 线格式错 | 句子去 `$`（`GPGGA,…` 裸地址起始） | `dollar` |
| 51 | `nmea_neg_missing_crlf` | 线格式错 | 流末句无 CRLF 裸结束 | `crlf` |
| 52 | `nmea_neg_lf_only` | 线格式错 | 行尾仅 LF（`0A`）无 CR | `crlf` |
| 53 | `nmea_neg_truncated_tcp` | 线格式错 | TCP 流在字段中间结束（半句无闭合，挥手前） | `truncat` |
| 54 | `nmea_neg_udp_truncated` | 线格式错 | UDP 报文尾无 CRLF（半句封入数据报） | `datagram` |
| 55 | `nmea_neg_udp_cross_datagram` | 线格式错 | 一句拆进两个数据报（报文边界切在句中） | `datagram` |
| 56 | `nmea_neg_start_bang` | 线格式错 | `!` 起始（`!AIVDM,…` AIS 形态，§3.6 排除项） | `start` |
| 57 | `nmea_neg_unknown_talker` | 地址错 | talker 不在 §3.2 值域表（`ZZ`） | `talker` |
| 58 | `nmea_neg_unknown_type` | 地址错 | formatter 不在支持集（`XYZ`） | `type` |
| 59 | `nmea_neg_talker_p_standard` | 地址错 | `P` 被当标准 talker（`$PGA,…` 五字符地址误用） | `talker` |
| 60 | `nmea_neg_field_count_short` | 字段错 | GGA 12 字段（尾部字段缺失，逗号数不足） | `field` |
| 61 | `nmea_neg_field_count_extra` | 字段错 | GGA 16 字段（追加多余尾字段） | `field` |
| 62 | `nmea_neg_lat_over` | 值域错 | 纬度 `9030.0000`（dd=90 且分>0，越 90°） | `latitude` |
| 63 | `nmea_neg_lon_over` | 值域错 | 经度 `18030.0000`（越 180°） | `longitude` |
| 64 | `nmea_neg_minutes_over` | 值域错 | 分 `60.0000`（`4860.0000`，分 ≥60） | `minute` |
| 65 | `nmea_neg_direction_char` | 值域错 | 纬半球 `X`（∉ N/S） | `direction` |
| 66 | `nmea_neg_time_out_of_range` | 值域错 | 时间 `253519.00`（hh=25 越界） | `time` |
| 67 | `nmea_neg_date_out_of_range` | 值域错 | 日期 `320394`（dd=32 越界） | `date` |
| 68 | `nmea_neg_status_char` | 值域错 | RMC 状态 `C`（∉ A/V） | `status` |
| 69 | `nmea_neg_gsa_mode_char` | 值域错 | GSA 模式 `X`（∉ M/A） | `mode` |
| 70 | `nmea_neg_gsa_fix_type` | 值域错 | GSA 定位维度 `4`（∉ 1/2/3） | `fix` |
| 71 | `nmea_neg_sentence_length` | 长度错 | 83 字节句（82 上界 +1，§3.1） | `length` |
| 72 | `nmea_neg_checksum_mismatch` | 校验错 | `*6A` ≠ 句内 XOR 复算 `*69` | `checksum` |
| 73 | `nmea_neg_checksum_hex_width` | 校验错 | `*` 后一位 hex（`*9`）——宽度非恰 2 | `checksum` |
| 74 | `nmea_neg_proprietary_no_checksum` | 校验错 | `$PGRME,…` 无 `*hh`（专有句强制，§3.3） | `checksum` |
| 75 | `nmea_neg_gsv_seq_correlation` | 关联错 | GSV 序号跳变（msg 1→3，total=3，§5 唯一句间关联） | `sequence` |
| 76 | `nmea_neg_carrier_layer_missing` | 配置/载体错 | 层链 `[{"nmea":{}}]` 直连（缺 tcp/udp） | `carrier` |
| 77 | `nmea_neg_carrier_conflict` | 配置/载体错 | tcp 层链 + 会话 `transport:"udp"` 声明矛盾 | `carrier` |
| 78 | `nmea_neg_port_undeclared` | 配置/载体错 | 非 10110 端口未显式声明（静默回退禁止） | `port` |
| 79 | `nmea_neg_address_family_mismatch` | 配置/载体错 | IPv6 地址配 IPv4 层链（`[ip,tcp,nmea]` + v6 地址）或反向 | `family` |
| 80 | `nmea_neg_error_propagation` | 错误传播错 | validator 已知校验和错误被吞、任务 completed/0 packet 假成功 | `propagat` |

**不得误报为 planner error 的合法协议事件**（防误报，N-21 两态声明）：**标准句无校验和**（正例 22——规范可选，旧稿"缺 *xx 即负例"废除）、观测模式坏校验和句（正例 17——`checksum_value:6A` 的观测形态，引擎生成并原样输出，expect 不含 error）、RMC 状态 V/空字段（正例 7）、GGA 质量 0 空字段（正例 4）、GSA 稀疏空槽与 2D 空 VDOP（正例 10/11）、GSV SNR 空字段（正例 14）、VTG 磁航向空（fixture）、校验和 `*00`（VTG fixture，数值 0 合法）、空字段占位（全部可空字段）、多播 UDP 目的（正例 40）。只有配置、线格式、字段、值域、长度、关联、载体错误进入负例。

## 8. 边界

- **句长上界**：82 字符含 `$` 与 CRLF（§3.1）——上界句正例 36（`$PXYZ,P×71*77` 恰 82B）；相邻 83B 负例 71；最短合法句（全空字段 ZDA 形态）为声明边界不设例（validator 不设下限）。
- **度分值域（N-12 枚举）**：纬 dd 00-90 / 经 ddd 000-180 / 分 00-59.9999 / 半球 N-S-E-W——正例边界：纬 0°（`0000.0000,N`）与 90°（`9000.0000,N`）、经 0°（`00000.0000,E`）与 180°（`18000.0000,E`）、分满值 `59.9999`、南/西半球（`S`/`W`）；负例相邻/越界：90°30′、180°30′、分 60、半球 X（62-65）。度分小数位 2-4 位并存（⑤），fixture 钉死 3 位（基线）与 4 位（边界）两形态。
- **时间/日期/状态/模式值域**：hh 00-23（负例 25 时）、dd 01-31 与 mm 01-12（负例 32 日）、RMC 状态 A/V（负例 C）、GSA 模式 M/A（负例 X）与维度 1/2/3（负例 4）、fix quality 0-8（正例代表 0/1/2/4，5-8 值域声明不设例，validator 校验）、RMC 模式 A/D/E/N（fixture A 与 N，D/E 声明）、ZDA 时区 ±00-±13（正例 +08/-05 两形态，±13 满值声明不设例）。
- **TCP 组帧**：段界可落 `$` 后（正例 31，split offset 1）、字段内（32，lat 第 4 字节处 offset 20）、校验和 hex 内（33，两位 hex 之间 offset 67）、CR 与 LF 之间（34，offset 69）——四种切位各一例；多句粘连单段（30，RMC+VTG 115B 段内 2 个 CRLF）；30 句 ×70B=2100B 打包跨 2 段（35，MSS 1460）；**段界不改变句内字节**（句子字节与单段形态完全一致，XOR 不变）。
- **UDP 边界**：一报文一句（37）/一报文 3 句 185B（38）/多播目的 239.192.0.1:10110（40）；报文边界不切句（54/55 负例双向：尾无 CRLF 与句跨报文）；**广播目的形态显式不产生**（§1 边界⑥）。
- **v4/v6**：独立 fixture（192.0.2.69→198.51.100.69 与 2001:db8::69→2001:db8::100:69），同一逻辑句字节必须一致，仅外层 IP 头与偏移（TCP 54/74、UDP 42/62）不同；IPv6 断言用 `ipv6.nxt`（=6/17）+ 显式地址，EtherType 0x86DD 仅作辅助（旧稿单写 EtherType 不稳，N-22 勘误）。
- **多会话/并发**：≥2 独立四元组按序展开（正例 22）/两会话 `concurrent:true` 交错（正例 23）——句子流与 GSV 序列互不串用；第二会话包号起点 = 前会话总包数 + 1。
- **RST/重连**：RST 中断（46，`tcp.flags.reset==1`、其后无句子帧、无挥手）；重连（47，新四元组、句子流重启、无恢复语义）；FIN 由全部 TCP 正例 `terminates=true` 承载——v1.3 §4 清单"FIN/RST 或异常中断"双形态闭合。
- **校验和口径**：标准句可选（22 正例）/专有句强制（74 负例）/大写 fixture 钉死（21 正例，`*6E` 字母位）/小写不产生（⑤声明）/`*00` 数值 0 合法（VTG fixture）/XOR 复算全 fixture 可验（20 正例 + 用例 §3 字节基线表）。
- 不得产生回绕长度或超量分配（句长 ≤82 硬校验；无未限定 buffer）。

## 9. 原子 ID 与完成定义

**ID 权威 = 用例文档 §2**：设计与 testcase/cases 使用同一 80 个语义 ID 集合与顺序（49 正 + 31 负）。其中 `nmea_tcp_wf_carrier_layer_missing` 是故意保留的游离字段/缺承载层负例，用于验证 C4 锚词传播，不是正例配置入口；设计 §10 D7/D8 对该故障形状作登记。

**正例 49 条按簇**（编号 = 用例文档 §2 行号）：基线（1）；句型字段族（2-19：GGA 4 例/RMC 2/GSA 4/GSV 3/VTG/GLL/ZDA 各 1-2/$P 1）；校验和族（20-22：复算/大写/省略）；talker 族（23-25：GN/GL/II）；值域边界族（26-29：纬/经/分/半球）；TCP 组帧族（30-36：粘连/四切位/跨 MSS/82B 上界）；UDP 族（37-40：单句/多句/IPv6/多播）；地址与端口族（41-43：IPv6-TCP/非默认端口/多载体）；会话与流族（44-47：多会话/并发/RST/重连）；观测与双输出（17：坏校验和观测模式；49：GQ talker 代表值，仍共用 pcap/NIC 断言契约，不是专项一致性例）。

**负例 31 行（50-80）**：逐故障输入一行一例，与 §7 表一一对应——线格式×7（50-56）、地址×3（57-59）、字段×2（60-61）、值域×10（62-71，含长度）、校验和×3（72-74）、关联×1（75）、载体×4（76-79）、传播×1（80）；`wire_fault` 31 值枚举见 §6（三方同序）。

**实现与验收定义**：本文件定义 `tcp→nmea` / `udp→nmea` 层链、线格式、生命周期和 cases 断言目标；不把目标写成已完成实现。实现、registry/translate 接线、pcap/NIC suite 复跑和双载体共存输出均属于后续缺口，需以实际代码与运行证据单独验收。

**完成验收对照（v1.3 §8.2）**：① 三方一致（用例 §2 权威/§8 清单/JSON 实况）——脚本核验；② 两条主线（代码设计逻辑 + 用例覆盖）——本 v2.0.0 修复轮为报告 23 findings 逐条落，待复验；③ 原子覆盖——一行一例（§7 单一注入）；④ 失败用例先行——负例锚词钉死单一字面值；⑤ 锚词一致——§7 与用例 §5 逐行同序同词；⑥ pcap+NIC 双输出契约——§1 六项；⑦ 待实现标记——§1 边界与 §8 声明逐项；⑧ 审查轮次入修订记录——§10。

## 10. 层链迁移契约与设计审计（D1-D8，2026-09-30）

| ID | 结论 | 证据/去向 |
|---|---|---|
| D1 | 地址只住 `layers[].ip`，端口只住 `layers[].tcp`/`layers[].udp`，业务字段只住终结层 `layers[].nmea`；数量由结构键驱动 | `nmea.json` 80 例全量机读审计；49 正例无顶层地址/端口/协议子映射 |
| D2 | 标准链为 `[ip,tcp,nmea]` 或 `[ip,udp,nmea]`；NMEA 是承载终结层，双载体由会话 `transport` 表达 | §2、§6；负例 76/77 专门验证缺承载与冲突；正例 41/43 的 tcp+udp 并列层链登记为 C2 迁移缺口 |
| D3 | NMEA 依赖 IP + TCP/UDP；失败在 validator 返回 task error，中断任务，不重试；UDP 不伪造握手 | §5、§7；负例 76–80 |
| D4 | `sessions/events/wire_fault` 均住 `layers[].nmea`；四元组分别住 IP 与承载层；GSV 序号由事件字段显式给出 | §3–§6；JSON 每例层内字段可定位 |
| D5 | 顶层 `nmea`、地址、端口禁止作为正例入口；**41/43 是已登记的多载体迁移缺口，不得作为 C2 已完成证据**；负例 76 故意保留缺承载层与顶层旧字段的双键形状；其他负例均保留单一故障并带锚词 | C1/C4 审计；§7；G-NMEA-3 |
| D6 | `flow_control`/`strategy_fc` 为 cases 驱动兄弟键（本批未使用）；会话并发是终结层编排字段，不隐式复制 | §5/§6，正例 44/45 |
| D7 | 31 个负例不清洗为正例，严格 `{expect_error,error_contains}`；故意违规层链仅用于判错 | §7 与 testcase §5 同序 |
| D8 | 未接线能力与真实 suite/NIC 复跑均登记为缺口，不以空 PCAP 宣称支持；41/43 的 tcp+udp 并列层链另登记为严格 C2 迁移缺口 | G-NMEA-1/G-NMEA-2/G-NMEA-3：需补齐 registry/translate、双输出复跑，并收敛多载体层链形状 |

### 10.1 P1 矩阵与三张子表

| 规范要求 | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|
| 句结构、CRLF、XOR、82B 上限 | 接收机持续推送 | nmea layer/validator 尚待接线 | G-NMEA-1 |
| TCP 流重组与 UDP 数据报边界 | 网关单播/多播 | planner/worker 尚待接线 | G-NMEA-1 |
| 七句型与 `$P` 字段值域 | 定位/卫星/航行数据 | 仅文档与 cases 契约 | G-NMEA-1 |
| FIN/RST/重连/并发会话 | 断流重启、多设备网关 | 目标配置已登记，未实测 | G-NMEA-2 |

| 命令×响应码 | 结论 |
|---|---|
| NMEA 无命令/响应码 | 不适用；单向通知流，§5 明确无事务 |

| 数据形态变体 | 用例 |
|---|---|
| 七句型、专有句、校验和省略/错误、TCP 分段、UDP 多句、v4/v6 | 1–49；失败形态 50–80 |

| 商业行为 | 用例映射 |
|---|---|
| 接收机持续推送/多星座/网关多设备/断流重连 | 1–25、44–47 |
| TCP/UDP 网关单播、多播、IPv6 | 30–43 |

### 10.2 三路对照与候选方案

| 路径 | 依据/行为 | 取舍 |
|---|---|---|
| 标准/公开规范 | NMEA 0183 v4.10；gpsd `NMEA.txt` 字段顺序与 XOR 口径 | 作为字段和值域底线 |
| 商业/现网 | u-blox/GARMIN 示例、NMEA-over-TCP 网关 10110 与 4001 惯例 | 作为 fixture 与端口场景，不推导真实定位 |
| 开源实现 | gpsd NMEA parser 的逐句校验与流式重组思路 | 借鉴状态与边界，不复制代码 |

| 候选方案 | 优点 | 缺点 | 结论 |
|---|---|---|---|
| TCP/UDP 通用终结层 + sessions/events | 与层链统一、可复用流重组 | 需实现双载体 planner | 采用 |
| 协议专用 raw-IP 自驱发包 | 配置短 | 破坏承载层职责，端口/握手难对账 | 不采用 |

### 10.3 依赖、性能、八要素与门1

- 依赖与错误：IP/承载层先成功；NMEA validator 失败返回带锚词 task error，停止当前任务且不重试；不产出外壳成功。TCP 连接由承载层负责，NMEA 不自动应答。
- 性能验收：目标为流式逐句生成，不聚合全量；基线单句、30×70B 跨 MSS、三并发会话及背压场景分别测包/秒、吞吐、内存、队列与 CPU；pcap 用 payload/frames 校验，NIC 用 tcpdump 同一断言集校验。
- 八要素：文件为 registry/validator/planner/translate 与三份契约；接口为 layer config→事件→帧；结构为 `[ip,carrier,nmea]`；流程为 validate→plan→build→write；错误为 task error；边界为 82B/队列有界；冲突为旧扁平字段与承载职责；回滚为仅回退本协议三文件改动。
- 动态字段清单（存量审计）：顶层可动态字段 = `src_ip`/`dst_ip`/`src_port`/`dst_port`/`nmea`（旧扁平）；层链形态下迁入位置：`layers[].ip.src/dst`、`layers[].tcp.src_port/dst_port`、`layers[].udp.src_port/dst_port`、`layers[].nmea.sessions[].events[]`；事件内字段（talker、type、时间、经纬度、卫星参数、状态、模式、校验和）均为 fixture 常量，**当前 cases 无运行期策略字段**；序号算法 = sessions 顺序索引（实现期放 nmea planner）。
- 门1（静态 Gate-1）：① 顶层旧键清单 = `{src_ip, dst_ip, src_port, dst_port, nmea}` —— 49 正例机读审计全无残留；② 会话/事务/关联/时间线 = `sessions[]`（transport/termination/pack/split_hint + events[]）、无事务（单向流）、关联 = GSV 序号显式字段、时间线 = 句子周期输出 + RST/重连节点；③ 动态字段清单见上；四元组/业务/序号三行登记完整；**严格 LayerChain 执行仍阻断于 G-NMEA-1/G-NMEA-3**。

### 10.4 能力缺口登记（G-NMEA-*，含证据定位）

| 缺口编号 | 缺口内容 | 证据定位（文件:行） | 迁入计划 |
|---|---|---|---|
| G-NMEA-1 | registry 缺 NMEA `Fields` 元数据（仅 `FieldContract` 端口默认值） | `trafficgen/internal/core/layers/registry.go:689` `LayerSchema{Name:"nmea", FieldContract:...}` 无 `Fields` | 在 registry 补充 `Fields: map[string]FieldMeta{...}` 定义所有终结层可配置字段（sessions/events/talker/type/time/lat/lon/...），经 validator 校验后方可声称严格层链可执行 |
| G-NMEA-2 | planner/translate 缺 `translateTerminalConfig` 分支 `case "nmea"`；pcap/NIC suite 未复跑 | `trafficgen/internal/core/layers/chain_planner_translate.go:792` `translateTerminalConfig` 无 `case "nmea"` 分支（当前 case 列表止于 kerberos/ntlm/sstp） | 在 `translateTerminalConfig` 增加 `case "nmea": ...` 将 `spec.NMEA` 映射为 `layers[].nmea.sessions[]`；随后以 80 例 JSON 跑 pcap/NIC 双输出 suite 闭环 |
| G-NMEA-3 | 多载体严格 C2 形状未收敛（正例 41/43 保留 tcp+udp 并列层链） | `trafficgen/test/protocol_pcap/cases/nmea.json` 正例 41/43 `layers` 含 `tcp` 与 `udp` 并存 | 后续拆分为独立载体用例（TCP 组、UDP 组），或 registry/validator 明确支持多载体层链形状后再合并 |

**结论**：上述三缺口均未闭环，**不得宣称严格 LayerChain 已可执行**；本版文档与 80 例 JSON 仅为语义契约与静态形状对齐，待代码补齐后另行验收。

## 11. 修订记录

- v1.0.0（2026-08-20）：旧稿首版（14 正 + 6 负；配置 v1.0 旧式 `{"protocol":…,"config":{…}}` 包裹 + `sentences:4` 计数式；负例三锚词候选列表；无逐字段表/无长度公式/无 fixture hex/无包数算式/无业务场景节/无状态机声明）。
- v2.0.0（2026-09-02，v1.3 重写级修复轮）：独立审查报告（docs-bacnet，/tmp/nmea_v13/report.md）23 findings = C 10 / D 8 / N 5 + §0 行为面枚举 ~92 测试点逐条落，20 → **80 例（49 正 + 31 负）**。逐条落点：**N-1（C）** 并发会话——§1/§4⑦/§5/§6 `concurrent:true` + 正例 45，#11 旧例拆分为按序展开（44）与并发交错（45）；**N-2（C）** 配置形状——§6 顶层 layers + sessions[]/events[] 重写（harness 对齐），事件级字段数组 + 会话级 transport/termination/pack/split_hint；**N-3（D）** pcap/NIC 双输出契约段——§1 六项式（offload 不影响句内 XOR 升级为契约），#17 保留为专项观测例；#49 为 GQ talker 代表值；**N-4（C）** 负例原子拆分——6 行三锚词候选 → 31 行单一注入单一主锚词（§7）；**N-5（C）** wire_fault 8 值 → 31 值三方同序映射（§6/§7/用例 §5），**"坏 JSON"外类故障删除**（ASCII 句子协议无 JSON 成分），`boundary` 枚举改 `udp_truncated`/`udp_cross_datagram`；**N-6（D）** 补 `nmea_neg_error_propagation`（负例 80）；**N-7（C）** §1④ 版本化实测基线（无 dissector/无 nmea.* 字段/无 DecodeAs 依赖）+ 非默认端口正例 42（4001）+ 未声明非默认端口负例 78 + 偏移表 54/74/42/62（§2）；**N-8（C）** FIN/RST/重连/保活——§5 口径 + 正例 46（RST）/47（重连），全部 TCP 正例 terminates=true，UDP 无连接声明；**N-9（C）** 句型原子化——8 句型 9 例打包式 → 逐句型逐字段 18 例（GGA 4/RMC 2/GSA 4/GSV 3/VTG/GLL/ZDA/$P）；**N-10（C）** talker 变体——GN/GL/II 三正例（23-25）+ 值域表（§3.2）+ `!` AIS 起始显式排除（§3.6 + 负例 56）；**N-11（D）** 校验和口径引规范原文落字——标准句可选（①"the checksum is optional for standard sentences"）正例 22 + 专有句强制负例 74，旧"缺 *xx 即负例"废除；**N-12（D）** 度分值域边界枚举——正例 26-29（0/满度/59.9999/南西）+ 负例 62-65 原子拆分；**N-13（N）** GSV 序号关联负例 75 + UDP 多播一例（40）/广播显式不产生（§8）；**N-14（C）** 逐字段规格表——§3.4 七句型 + $P 逐字段（类型/宽度/值域/空字段形态/出处）+ §3.5 行长公式表（fixture 实测核对）；**N-15（C）** 业务场景分析节（§4 现网九场景 + 五层逐层 + 事务/状态机/流关联/多流显式不适用声明）+ §5 单向流声明；**N-16（D）** fixture 常量表 + 逐句 hex 基线 + XOR 复算值 + 固定偏移表（用例 §3）；**N-17（D）** 包数算式——§5/用例 §1"包数约定"（TCP=3+N+4、RST=3+N+1、UDP=报文数、多会话=Σ 起点+1），逐例重算（旧稿 #3 GGA=6、#12 UDP=6 拍脑袋值废除）；**N-18（D）** 用例 §2 依据列补齐；**N-19（N）** ID 权威改用例 §2，设计 §9 簇级图景；**N-20（N）** JSON notes 注册同步项登记（用例 §7）；**N-21（D）** 坏校验和观测正例（17）与负例 72 两态同源声明（§3.3/正例 17，"透明转发"改"生成并原样输出"）；**N-22（N）** IPv6 断言改 `ipv6.nxt` + 显式地址，EtherType 降辅助；**N-23（N）** 多载体术语与配置落点（§4/§6 会话级 transport + 正例 43）。**复验修正（提交前）**：全表 29 行 XOR/长度逐字节复算 + 七句型字段数核对，修正 4 处 fixture 结构性错误——GGA 无定位 13→14 字段（单位 M 归位 f10/f12）、RMC 状态 V 11→12 字段（course 空位补回）、GSA 满槽/手动 16→17 字段（卫星集补 `32` 成 12 星真满槽）、GSV 序列 10→11 星恰闭合（杂星 23 归位为 12、msg3 补 06 组）；受影响 XOR/长度/hex/断言同步重算，修正后全表 29 行复算通过。

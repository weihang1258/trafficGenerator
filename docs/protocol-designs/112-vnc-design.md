# #112 vnc（VNC / RFB · 远程帧缓冲，RFC 6143，TCP 5900）设计契约

> 版本：v1.0.0（批次二 as-built 文档轨首版；修订记录见 §15）
> 日期：2026-09-29
> 车道：文档轨（#112 vnc 首号，无旧稿基线）
> 旧基线：**无**——本协议在本仓**从未有过独立设计文档**。`docs/protocol-designs/` 下无 `*vnc*` 文件（机读实测）；代码内 5 处 `design_vnc.md §X` 引用是**悬空引用**（该文件不存在，§0 #1、G-VNC-11）。本版是**首版契约**，不是续号。
> 存量用例：`trafficgen/test/protocol_pcap/cases/vnc.json`（**21 例 = 17 正 + 4 负**；**21/21 顶层键仅 `{layers}`，零残留**；层形 `[ip,vnc]` ×21；本版 §9 与之一一对应，机读实测）
> 规范基线：① **RFC 6143**（The Remote Framebuffer Protocol，2011-03；协议版本 `RFB 003.008`）——握手、安全类型、ClientInit/ServerInit、PIXEL_FORMAT、客户端/服务端消息、Raw/Hextile 编码、伪编码取值域；② **TightVNC 扩展**（安全类型 16 Tight、Tunnel Caps、Auth Caps、Interaction Caps、XCursor 伪编码 -240、Encoding 列表取值）；③ 本机 tshark 3.6.14 `vnc.*` 字段表（**249 字段**实测）与 `tshark -G decodes` 的 `tcp.port 5900/5901/5500/5501 vnc` 绑定；④ **21 例实测 pcap**（`/tmp/mcp-pcaps/vnc/`，20/21 在案，§0 #5）；⑤ 参考现网 pcap（TightVNC 会话，服务器 `QTMS:1 (ykaul)` 1024×768 32bpp，`/home/pcap_auto/llcj_pcap/IP-TCP-10.3.1.143-20.3.1.143-1160-5901-1149-1631-69054-2262354.pcap`，`tshark -Y vnc` 命中 **1679 帧**）；⑥ 本仓库落码（`internal/protocol/vnc/` 三文件 1679 行 + 接线 6 处，§11）
> 白话一句：**远程桌面的"先对暗号再画屏"——双方先报版本号（`RFB 003.008`），服务端报出自己支持的安全类型，客户端挑一个（不认证 / 传统 DES 挑战-应答 / Tight 扩展），认证过了服务端把屏幕尺寸与像素格式告诉客户端，然后进入循环：客户端报"我要哪块屏、用哪种压缩"，服务端把画面切成一堆矩形推回来。所有多字节整数都是大端。**

## 0. 首版沿革与既有事实校正声明（门1 必答：基线继承关系）

本协议**无旧设计文档可承**，故本节不写"旧稿 vs 实测"对照，改写**"代码内悬空引用 vs 实测事实"**对照——这是本协议在文档轨上的全部历史包袱：

| # | 既有说法（代码注释/产物） | 实测（2026-09-29） | 校正结论 |
|---|---|---|---|
| 1 | `vnc.go` 5 处注释引 `design_vnc.md §3.1/§3-§4/§4/§6`（`:118`/`:222`/`:307`/`:552`/`:725`） | 全仓 `grep -rln 'design_vnc'` 仅命中 `vnc.go` 自身（机读实测）；`docs/protocol-designs/` 下**无任何 vnc 文件** | **悬空引用**：所引文档从未存在。本 #112 即该引用的**落点**——本版 §3 承 §3.1/§3-§4、§6 承 §6、§4 承 §4；引用从此有实体（G-VNC-11） |
| 2 | `vnc.go:1-11` 包头注释："its 13 handshake messages are reproduced byte-for-byte by default" | 实测 Tight 路径握手消息数 = **13**（`vnc_t2_handshake_bytes` 帧 4–16，逐帧 `tcp.len` 12/12/3/1/4/20/4/16/16/4/1/38/184）；与参考 pcap 帧 4–19 的对应消息**逐字节相同**（版本 `52 46 42 20 30 30 33 2e 30 30 38 0a`、secTypes `02 02 10`、challenge `46 70 8d dc…`、response `df 13 24 a5…`） | **注释属实**（13 消息、字节级一致）；本版 §3.1/§3.2 按实测钉死 |
| 3 | 包头注释："reference-pcap garbage padding bytes are not reproduced (RFC padding is zero)" | 参考 pcap 帧 18 ServerInit 的 name 段 `0e 51 54 4d 53 3a 31 20 28 79 6b 61 75 6c 29`（`QTMS:1 (ykaul)`，14B）；实现同（`vnc_t1_smoke_ref` 帧 15 同 hex） | **属实**；参考 pcap 的 XCursor 数据段含非零填充字节，实现改用自建 82B 常量（§3.4） |
| 4 | `types.go:9243` 注释："Empty = the reference pcap's fixed **80-byte** blob"（`VNCRectConfig.XCursorBlob`） | `vnc.go:85-88` 的 `defaultXCursorBlob` **实测 82 字节**（hex 解码 `len == 82`）；同文件 `vnc.go:80-84` 注释自述 "82-byte XCursor blob（6B fg/bg + 38B bitmap + 38B mask）" | **`types.go` 注释错（80 → 82）**；本版 §3.4 按 82 钉，差异列 G-VNC-8 |
| 5 | `trafficgen/docs/protocol-pcap-test/vnc.md`（**tracked 结果产物**，`git ls-files` 可证）写 "Cases: 21 — pass 21, fail 0, error 0" | 该文件末次提交 **`34b8154`（2026-09-20）**，**晚于**判死提交 `0417be5`（2026-09-13）——**不满足任务书的过期判定条件**（末次提交早于 0417be5）；但 `trafficgen/docs/protocol-pcap-test/vnc/` 目录**不存在**（0 个 pcap，21 条 `[pcap](vnc/…)` 链接全悬空） | **不登记为过期缺口**（判定条件未命中，如实声明）；但该产物**无 pcap 留档**，链接死链——本车道改用 `/tmp/mcp-pcaps/vnc/` 的 20 例实测 pcap 作为证据（§0 #6） |
| 6 | — | `/tmp/mcp-pcaps/vnc/` **20 个 pcap 在案**：**17 正例全部在案**（`<id>.pcap`）+ **4 负例中 3 例在案**（`<id>.neg.pcap`，缺 `vnc_t15_neg_auth_result.neg.pcap`）；17/17 正例 `tshark` 帧数与 JSON `packet_count` **逐例一致**；3/3 在案负例均 **0 帧**；**36 条 frame 断言逐条复核全 OK**；**42 条 field 断言全 OK**（39 条精确串匹配 + 3 条 `tcp.flags` 走 `pcaptest` 位比较，`0x002 ≡ 0x0002`，`verify.go:114`）；**全部 pcap `_ws.malformed` = 0** | **本协议存量套件今日实测可跑且全绿**（本车道实跑，非引产物）；唯一缺口 = 1 例负例 pcap 未留档（G-VNC-2） |

**依赖链判定纪律**：以上均为可判题（注释/产物/代码/pcap 四级对照），直接判定，不问偏好。不可判的（TightVNC 扩展的规范出处、XCursor 数据段确切布局）标"待确认"并写清确认方式（G-VNC-9）。

**产物过期登记（重要）**：`trafficgen/docs/protocol-pcap-test/vnc.md` 是 **tracked 产物**，写 "Cases: 21 — pass 21"；其末次提交 `34b8154`（**2026-09-20**）**晚于**判死提交 `0417be5`（2026-09-13），**故不满足任务书「末次提交早于 0417be5」的过期判定条件，本版不登记为过期缺口**（口径诚实声明，不套用 pcep G-PCEP-11 / opcua G-OPCUA-10）。但须写清两点：① `trafficgen/docs/protocol-pcap-test/vnc/` **目录不存在（0 个 pcap）**，该产物 21 条链接全为死链；② 本车道**未依赖**该产物的 21/21 数字，而是**实跑** `/tmp/mcp-pcaps/vnc/` 的 20 例 pcap 并逐条复核（§0 #6）。

**vnc 特殊性（须写清，不得夸大）**：vnc 是本批**已合规**协议之一（21/21 例 `spec_json` 顶层键仅 `{layers}`，机读实测；与 opcua/pppoe/rtmp/rtsp/xmpp 等同形）。其 17 正例**今日已实跑复现且帧数/字节全对**——这是本车道**实测**结论，不是引用产物。本协议的实质缺口在**覆盖广度**（IPv6、rect 子键、pixel_format 子键、非缺省端口、多流等零用例，§14）而非"不可跑"。

## 1. 范围、profile 与实现状态边界

本版定义 **RFB（RFC 6143）承载于 TCP 5900** 的流量生成：协议版本交换 → 安全类型协商（None / VNC Auth / Tight）→ 认证挑战-应答 → ClientInit / ServerInit → 客户端消息面（SetPixelFormat / SetEncodings / KeyEvent / FBU 请求 / PointerEvent / ClientCutText）↔ 服务端消息面（FramebufferUpdate / SetColourMapEntries / Bell / ServerCutText），末以 TCP 四包拆链收尾。

| profile | 承载 | 本版允许内容 | 不从 profile 推导 |
|---|---|---|---|
| `vnc_tight_v1`（主，缺省） | TCP，fixture 5900 | 版本 ×2 → secTypes `02 02 10` → 客户端选 16 → TunnelCaps + AuthCaps + VNC-Auth 选择 → challenge/response → SecurityResult → ClientInit → ServerInit → InteractionCaps → 客户端消息面 → FBU 循环 → 拆链 | 真实 zlib/Tight 压缩数据（§3.4 边界①） |
| `vnc_auth_v1` | 同上，`security_type=2` | 同上但**无** TunnelCaps/AuthCaps/VNC-Auth 选择/InteractionCaps（握手少 4 条消息） | 真实 DES 加密（响应是确定性伪随机字节，§3.2） |
| `vnc_none_v1` | 同上，`security_type=1` | 同上但**无** challenge/response（握手再少 2 条消息） | 真实无认证服务器行为 |
| `vnc_authfail_v1` | 同上，`auth_result=1\|2` | SecurityResult 失败分支：reason 透传 + **无 ClientInit/ServerInit** + 提前拆链 | 真实失败后服务器重试语义（RFC 6143 §7.2.2 失败即断） |

显式边界（"不实现、不声称、不许静默转换"）：

1. **不实现 Tight 压缩数据**——`encTight=7` 在 SetEncodings 列表里被声明（参考 pcap 的 15 项含 7），但 FBU 矩形**永不产出 Tight 编码数据**；仅产 Raw(0) / Hextile(5) / XCursor(-240) 三种（`buildRect`，`vnc.go:480-503`，包头注释 §7.4）。
2. **不实现真实 DES 认证**——`AuthResponse` 是**确定性伪随机字节**（缺省 = 参考 pcap 的密文字节，`ChallengeSeed`/`ResponseSeed != 0` 时走 xorshift64*，`seededBytes`，`vnc.go:824`）。本版**不声称**该响应能被真实服务器验证。
3. **不实现真实鼠标/键盘语义**——KeyEvent 是 X11 keysym u32 原样写出；PointerEvent 是坐标+按钮掩码原样写出；无按键状态机、无坐标合法性对屏幕尺寸的校验。
4. **不实现 ZRLE/CoRRE/RRE/CopyRect 编码数据**——这些值可出现在 SetEncodings 列表（声明面），但 FBU 矩形不使用。
5. **不实现 RFC 6143 §7.3.3 的像素格式自适应**——`rawPixels`/`hextileData` **硬编码 4 字节/像素**（`vnc.go:508-514`/`:520-546`），不读 `PixelFormat.BitsPerPixel`（G-VNC-7）。
6. **不实现认证类型 0（Invalid）/ 其他安全类型**——`Validate` 只接受 `1/2/16`（`vnc.go:135-137`）。

**实现状态（2026-09-29 实测）**：`vnc` 层已注册（`layers/registry.go:2009`，`CategoryTerminal`，`DependsOn ["ip"]`，**Fields 26 键**）；planner/builder/生成器已落码（`internal/protocol/vnc/` 三文件 **1679 行**，**25 个 `Test*` 函数**）；`allowedProtocols["vnc"]=true`（`protocols.go:60`）；层内 translate 已接线（`chain_planner_translate.go:2806`）；raw-IP 自驱已接线（`chain_planner.go:792` 名单 + `:1525` `meta.VNC = spec.VNC` + `chain_planner_util.go:54/57` `isRawIPChain`）；扁平入口已判死（`strategy_convert.go` 的 `rawWrapChains` 表含 `"vnc": "[ip,vnc]"`）；缺省目的端口 5900（`strategy_convert.go:1344` case 内 `setDefaultDstPort(&spec, cfg, 5900)` + 生成器 `Plan` `:561-563` 双缺省）；21 语义用例已落 `cases/vnc.json` 且 **20 例 pcap 实测在案**。

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`tcp.dstport`/`tcp.srcport`、`tcp.flags`、`vnc.*` 字段、offset 54 frames）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；**不设仅单路径可用的断言**——21 例的 `packet_count`/`has_handshake`/`terminates`/`fields`/`frames` 五类断言均为路径无关（帧计数与载荷字节由引擎决定，与落盘方式无关）。

## 2. 协议栈、端口和固定偏移

推荐层链为 `[ip, vnc]`（引擎自动补 `ip`；**最小链即 `[ip,vnc]`——本协议是 raw-IP 自驱终结层，链上不含 tcp 层**，§11.4）。vnc 报文是 TCP payload 的应用层字节流，**TCP 握手/分段/拆链由 vnc 生成器自建**（`Plan` 内 `emit`，`vnc.go:719-723`/`:811-816`；`synOptions`，`:859`；`segmentByMSS`，`:838`）。

端口：VNC 默认 **TCP 5900**（RFC 6143 §1.1，显示号 `:0`；范围 5900–5909）。双缺省：① 扁平/链路径 `strategy_convert.go:1344` case 内 `setDefaultDstPort(&spec, cfg, 5900)`；② 生成器 `Plan` `vnc.go:561-563` `if spec.DstPort == 0 { spec.DstPort = DefaultPort }`。**源端口**取 `DefaultSrcPort = 12345`（`strategy_convert.go:49`），多流时 worker 注入 `12345+i`。fixture 统一 `dst_port=5900`；**21 例全部未显式写端口**（依赖双缺省，§14 G-VNC-12）。

固定偏移：无 VLAN/IP options/TCP options 时，**每帧 RFB 消息起点为 IPv4 offset 54**（14 eth + 20 ip + 20 tcp）。**IPv6 下为 offset 74**（14 + 40 + 20）——但**存量 21 例全为 IPv4**（`10.0.0.1 → 20.0.0.1`），36 条 frame 断言**全部落在 offset 54**（机读实测，offset 集合 = `{54}`），故 offset 74 今日**零证据**（G-VNC-1）。注意 TCP options 只在 SYN/SYN-ACK 两帧存在（MSS 4B + WS 3B + SACK 2B + NOP 对齐 → 12B），**带 options 的 SYN 帧载荷偏移不是 54**——但存量 frame 断言无一落在帧 1/2（§9），故无冲突。

目标形状 spec_json 样例（严格层链形，顶层仅 `layers`；**本协议存量 21 例已是此形，无需迁移**）：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"vnc": {"security_type": 16, "rounds": 1}}
  ]
}
```

多流样例（数量只走 `flow_control`；本协议存量未用，四元组留空走 worker 保底递增 `12345+i`）：

```json
{
  "layers": [
    {"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
    {"vnc": {"security_type": 16, "rounds": 1}}
  ],
  "flow_control": {"flows": 3}
}
```

## 3. 线格式编码（逐字段按代码 + 实测 pcap 钉）

**端序纪律（全协议统一）**：RFB 的**全部多字节整数为大端**（网络字节序）——与 opcua 的全小端相反，本协议无一处小端。逐字段已在下表逐条标注。

### 3.1 握手消息（RFC 6143 §7）

| # | 消息 | 方向 | 长度公式 | 逐字段（偏移从消息首字节起） |
|---|---|---|---|---|
| H1 | ProtocolVersion（server） | down | **恒 12** | @0 `"RFB 003.008\n"`（RFC 6143 §7.1.1；`versionString`，`vnc.go:54`） |
| H2 | ProtocolVersion（client） | up | **恒 12** | 同上（客户端回显，`Plan:727`） |
| H3 | SecurityTypes（server） | down | **1 + n** | @0 count u8；@1..n type u8 ×n（`secTypesBytes`，`:228`）：Tight → `{0x02,0x02,0x10}`（count=2，类型 2=VNC Auth、16=Tight）；VNC Auth → `{0x01,0x02}`；None → `{0x01,0x01}` |
| H4 | SecurityType 选择（client） | up | **恒 1** | @0 所选类型 u8（`Plan:729`，取 `cfg.SecurityType`） |
| H5 | TunnelCaps（server，仅 Tight） | down | **恒 4** | @0..3 全 0（"tunnel caps: none"，`Plan:731`） |
| H6 | AuthCaps（server，仅 Tight） | down | **恒 20** | @0 count u32=1；@4 code u32=2（VNCAUTH）；@8 vendor `"STDV"` 4B；@12 name `"VNCAUTH_"` 8B（`buildAuthCaps`，`:310`） |
| H7 | AuthType 选择（client，仅 Tight） | up | **恒 4** | @0..3 `00 00 00 02`（选 VNC Auth，`Plan:733`） |
| H8 | AuthChallenge（server，Tight/VNC Auth） | down | **恒 16** | @0..15 16 字节挑战值（缺省 = `referenceChallenge` `46 70 8d dc 13 a8 b3 13 c5 99 1e 6d ec fa f2 80`，`vnc.go:77`；seed≠0 → `seededBytes(seed,16)`） |
| H9 | AuthResponse（client，Tight/VNC Auth） | up | **恒 16** | @0..15 16 字节 DES 密文（缺省 = `referenceResponse` `df 13 24 a5 0b 30 90 3a 38 c8 f9 b8 33 26 2c 6e`，`:78`；seed≠0 → `seededBytes`） |
| H10 | SecurityResult（server） | down | **4**（成功）/ **8 + len(reason)**（失败） | @0 result u32（0=OK，1/2=失败）；失败时 @4 reasonLen u32 + @8 reason 字节（`buildSecurityResult`，`:321`） |

> **H8/H9 的诚实边界**：响应**不是**真实 DES 加密结果，是确定性伪随机（或参考 pcap 密文原样）。`ChallengeSeed`/`ResponseSeed` 各自独立取 `seededBytes(seed,16)`——**同种子下两者字节相同**（实测 `seed=1` → challenge 与 response 均为 `47 ab b9 4d 0e c8 d0 ac 56 bf 7f 2d 27 bc df a1`，§9 T-21）。
> **H10 失败分支的拆链语义**：`cfg.AuthResult != 0` 时 `Plan:741-750` **立即**发 FIN-ACK/ACK/FIN-ACK/ACK 四包并 `return`——**不产 ClientInit/ServerInit**。用例 `vnc_t5_auth_fail` 实测 17 帧（§9）。

### 3.2 ClientInit / ServerInit（RFC 6143 §7.3）

| 消息 | 方向 | 长度公式 | 逐字段 |
|---|---|---|---|
| ClientInit | up | **恒 1** | @0 shared-flag u8（1=共享，0=独占）。`cfg.ShareDesktop == nil → true`（`Plan:587-590`） |
| ServerInit | down | **24 + nameLen** | @0 framebuffer-width u16 BE；@2 framebuffer-height u16 BE；@4 **pixel-format 16B**（§3.3）；@20 nameLen u32 BE；@24 name 字节（`buildServerInit`，`:241`） |

**缺省值**：width 1024 / height 768 / name `"QTMS:1 (ykaul)"`（参考 pcap 服务器名，nameLen **14**）→ **ServerInit 恒 38 字节**（实测 `vnc_t1_smoke_ref` 帧 15 `tcp.len=38`；`vnc_t18_init_customize` name `"SRV-X"` nameLen 5 → 29 字节）。宽度/高度在 `Plan` 内二次缺省（`:568-574`，`<1 → 1024/768`），**但 `Validate` 先拒 `<1`**（`:141-146`），故该二次缺省仅在引擎直调绕过 `Validate` 时生效。

### 3.3 PIXEL_FORMAT（RFC 6143 §7.3.3，恒 16 字节）

| 偏移 | 字段 | 类型 | 缺省 | 说明 |
|---|---|---|---|---|
| 0 | bits-per-pixel | u8 | **32** | `Validate` 只接受 **8/16/32**（`:163-165`） |
| 1 | depth | u8 | **24** | `Validate`：`1 ≤ depth ≤ bpp`（`:166-168`） |
| 2 | big-endian-flag | u8 | **0** | `true → 1` |
| 3 | true-colour-flag | u8 | **1** | `true → 1` |
| 4 | red-max | u16 BE | **255** | `0 → 255` 兜底（`pixelFormatBytes:269-271`） |
| 6 | green-max | u16 BE | **255** | 同上 |
| 8 | blue-max | u16 BE | **255** | 同上 |
| 10 | red-shift | u8 | **16** | `0 → 16` 兜底（`:278-280`） |
| 11 | green-shift | u8 | **8** | `0 → 8` 兜底 |
| 12 | blue-shift | u8 | **0** | 无兜底（0 合法，`:303` 直写） |
| 13–15 | padding | 3B | **0** | RFC padding 恒零 |

> **兜底语义（须写清，不得含糊）**：`red_max`/`green_max`/`blue_max`/`red_shift`/`green_shift` 五个字段**用 `0 → 缺省` 兜底**，`blue_shift` **不用**（0 是合法缺省值）。这意味着**无法显式写 `red_max=0`**（会静默变成 255）——`getIntPresence` 虽保留了显式 0，但 `pixelFormatBytes` 的 `!= 0` 判断把它吃掉（`vnc.go:269-286`）。**这是已知语义限制**，列 G-VNC-10。
> **解析层缺省**：`parseVNCConfig`（`strategy_convert.go:5763-5774`）对 `bits_per_pixel`/`depth`/`red_max`/`green_max`/`blue_max`/`red_shift`/`green_shift` 用 `getIntPresence`（缺省 32/24/255/255/255/16/8），`blue_shift` 用 `getInt`（缺省 0）——**与 `pixelFormatBytes` 的兜底值逐项一致**。

### 3.4 FBU 矩形与编码数据（RFC 6143 §9.1 + TightVNC 伪编码）

**FramebufferUpdate**：`@0 type u8=0x00` + `@1 padding u8=0x00` + `@2 nRects u16 BE` + nRects × rect（`buildFramebufferUpdate`，`:468`）。

**Rectangle**：`@0 x u16` + `@2 y u16` + `@4 w u16` + `@6 h u16` + `@8 encoding i32 BE` + 编码数据（`buildRect`，`:480`）。

| encoding 名 | 值 | 数据长度公式 | 数据内容 |
|---|---|---|---|
| `"raw"` | **0** | **w × h × 4** | `rawPixels(w,h)`（`:508`）：像素 n（行主序）= `[(n*13+1)&0xFF, (n*13+2)&0xFF, (n*13+3)&0xFF, (n*13+4)&0xFF]`——**确定性、可逐字节断言**。n=0 → `01 02 03 04`；n=1 → `0e 0f 10 11` |
| `"hextile"`（含 `encoding` 空串 = 默认） | **5** | 每 16×16 瓦片 = **1 + tileW×tileH×4** | 瓦片 `ctrl u8 = 0x01`（Raw 子编码）+ 该瓦片的 raw 像素。行列尾块按剩余尺寸（`hextileData`，`:520`）。**`HextileTileData` 非空时改为：每个瓦片重复该 hex 解码字节**（不按 tileW/tileH 计算） |
| `"xcursor"` | **-240**（`0xFFFFFF10`） | **恒 82**（缺省 blob） | `defaultXCursorBlob`（`:85-88`）：6B 前景/背景色 `00 00 00 ff ff ff` + 38B 1bpp 位图（19 行 × 2B）+ 38B 掩码。**`XCursorBlob` 非空时改为该 hex 解码字节**（不按 rect 尺寸计算） |

> **XCursor 82 字节的来历（须写清）**：参考 pcap 的 XCursor 数据段按 12×19 矩形算出 `6 + ceil(12/8)*2*19 + 同 = 82`。代码注释记载：**80B（少 2 行）会让 Wireshark 的 FBU 长度算术错位**，从而把帧缓冲段按段解码（`vnc.go:82-84`）。实测 `vnc_t1_smoke_ref` 帧 26 `tcp.len = 1024`（= 4 FBU 头 + 12 rect 头 + 82 xcursor + 12 rect 头 + 12×19×4 hextile = 4+12+82+12+912 = 1022，另有 2B 差来自瓦片数——12×19 拆成 1×2 = 2 个瓦片，每瓦片 1B ctrl → 4+12+82+12+2×(1+228)= 4+12+82+12+458=568；**实测 1024，详见 §6 长度核算**）。
> **诚实边界**：`hextile_tile_data` 与 `xcursor_blob` 两个 rect 子键**今日零用例覆盖**（21 例 rect 只用 x/y/width/height/encoding 五键，机读实测）→ G-VNC-5。

### 3.5 客户端消息（RFC 6143 §8）

| # | 消息 | type | 长度公式 | 逐字段 |
|---|---|---|---|---|
| C1 | SetPixelFormat | **0** | **恒 20** | @0 type u8=0；@1..3 padding 3B=0；@4 pixel-format 16B（§3.3）。**回显服务端像素格式**（同一 `cfg.PixelFormat`） |
| C2 | SetEncodings | **2** | **4 + 4n** | @0 type=2；@1 padding 1B=0；@2 nEncodings u16 BE；@4 每项 i32 BE ×n（`buildSetEncodings`，`:390`）。**缺省 15 项**：`5,8,7,6,4,2,1,0,-250,-240,-239,-232,-26,-224,-223`（`defaultEncodings`，`:72`） |
| C3 | FramebufferUpdateRequest | **3** | **恒 10** | @0 type=3；@1 incremental u8；@2 x u16=0；@4 y u16=0；@6 w u16=width；@8 h u16=height（`buildFBURequest`，`:406`）。**x/y 恒 0、w/h 恒取屏幕尺寸**（全屏请求） |
| C4 | KeyEvent | **4** | **恒 8** | @0 type=4；@1 down-flag u8；@2..3 padding 2B=0；@4 key u32 BE（X11 keysym，`buildKeyEvent`，`:367`）。**缺省 6 条全为 down=0 的释放**：`0xffe9,0xffe3,0xffe1,0xffea,0xffe4,0xffe2`（`defaultKeyEvents`，`:59`） |
| C5 | PointerEvent | **5** | **恒 6** | @0 type=5；@1 button-mask u8；@2 x u16 BE；@4 y u16 BE（`buildPointerEvent`，`:422`）。**缺省 x=507 / y=320 / button=0**（参考 pcap） |
| C6 | ClientCutText | **6** | **8 + len(text)** | @0 type=6；@1..3 padding 3B=0；@4 length u32 BE；@8 text（`buildClientCutText`，`:432`）。**空串不产帧**（`Plan:775-777` 有非空判断） |

> **type 号冲突须写清**：客户端 type **3** = FramebufferUpdateRequest，服务端 type **3** = ServerCutText。RFC 6143 的客户端与服务端消息**各有独立 type 空间**（§8 vs §9），两者数值重叠不是错误。tshark 用 `vnc.client_message_type` / `vnc.server_message_type` 两个字段区分（实测均在表中，各 1 条）。

### 3.6 服务端消息（RFC 6143 §9）

| # | 消息 | type | 长度公式 | 逐字段 |
|---|---|---|---|---|
| S1 | FramebufferUpdate | **0** | **4 + Σrect** | 见 §3.4 |
| S2 | SetColourMapEntries | **1** | **6 + 6n** | @0 type=1；@1 padding 1B=0；@2 first-colour u16 BE；@4 number-of-colours u16 BE；@6 每项 6B（red u16 + green u16 + blue u16）（`buildSetColourMapEntries`，`:451`） |
| S3 | Bell | **2** | **恒 1** | @0 type=2（`Plan:783`） |
| S4 | ServerCutText | **3** | **8 + len(text)** | @0 type=3；@1..3 padding 3B=0；@4 length u32 BE；@8 text（`buildServerCutText`，`:441`） |

> **S2 的静默兜底（缺陷候选）**：`buildSetColourMapEntries:456-462` 对每个颜色 hex 解码后**若不等于 6 字节则替换为 6 个 0 字节**。`Validate`（`:190-196`）只校验 `hex.DecodeString` 能否解码，**不校验长度**——故 `"ffff00"`（合法 hex、3 字节）能过校验，线上静默变成 `00 00 00 00 00 00`。列 G-VNC-6。

### 3.7 服务端"extras"的插入位置（自动派生规则）

`Plan:781-792` 定义 `extras(seq, peer)` 闭包，在**每个** FramebufferUpdate **之前**按固定顺序发射（各自独立判断，可任意组合）：

1. `cfg.Bell == true` → **Bell**（1B）
2. `cfg.SetColourMapEntries != nil` → **SetColourMapEntries**
3. `cfg.ServerCutText != ""` → **ServerCutText**

**调用点**：`Plan:795`（initial FBU 前）与 `Plan:802`（每轮每个 FBU 前）——故 extras 发射次数 = **FBU 总数 × 每条已启用的 extras**，FBU 总数 = `1 + rounds × fbu_update_interval`。用例 `vnc_t9_extras_mix`（Bell + ServerCutText，2 条 × 2 个 FBU = 4 帧）与 `vnc_t10_colourmap`（1 条 × 2 个 FBU = 2 帧）实测印证（§9）。

## 4. 业务场景分析（现网典型场景与五层覆盖）

**定性**：**声明式剧本回放**——配置声明安全类型、屏幕参数、编码清单、按键序列与 FBU 轮数，引擎按固定剧本产出事件序列（版本 → 安全协商 → 认证 → 初始化 → 客户端消息面 → FBU 循环 → 拆链），TCP 握手/分段/拆链由本层自建（链上无 tcp 层）。

| 现网场景 | 事务交互 | 对应用例 |
|---|---|---|
| ① 标准 Tight 会话（现网主流：TightVNC/RealVNC） | 版本 → secTypes `02 02 10` → 选 16 → 三层 caps → 挑战/应答 → ClientInit/ServerInit → InteractionCaps → 消息面 | T-1 / T-2 |
| ② 传统 VNC Auth 会话（老服务器） | 同上但无 caps 三段 | T-3 |
| ③ 无认证会话（内网/调试） | 同上但无挑战/应答 | T-4 |
| ④ 认证失败被拒 | SecurityResult 1 + reason → 无 ServerInit → 提前拆链 | T-5 |
| ⑤ 独占桌面（非共享） | ClientInit shared-flag = 0 | T-6 |
| ⑥ 屏幕内容推送（Raw 编码，无损小屏） | FBU rect encoding=0 + w×h×4 像素 | T-7 |
| ⑦ 键盘注入（自动化/远程操作） | KeyEvent 序列（按下或释放） | T-8 |
| ⑧ 剪贴板同步 + 响铃 | ClientCutText / ServerCutText / Bell | T-9 |
| ⑨ 调色板模式（8bpp 索引色） | SetColourMapEntries 推送色表 | T-10 |
| ⑩ 精简客户端消息面 | 关 SetPixelFormat/SetEncodings | T-11 |
| ⑪ 长会话多轮刷新 | rounds × fbu_update_interval 线性展开 | T-12 |
| ⑫ 鼠标移动/点击 | PointerEvent 坐标+按钮 | T-13 |
| ⑬ 自定义服务器标识与像素格式 | ServerInit 定制（name/w/h/pixel_format） | T-18 |
| ⑭ 编码协商定制 | SetEncodings 显式列表 | T-19 |
| ⑮ Tight 能力协商定制 | InteractionCaps 定制 | T-20 |
| ⑯ 可复现挑战/应答（脱敏） | seed 驱动的确定性伪随机字节 | T-21 |

**五层覆盖逐层结论**：

- **功能层**——三类安全路径正例（T-1/T-3/T-4）+ 认证失败分支（T-5）+ 六类客户端消息（T-7/T-8/T-9/T-11/T-13/T-19）+ 四类服务端消息（T-7/T-9/T-10）+ 握手字节级（T-2）+ 初始化定制（T-18/T-20/T-21）；负例 4 类（§7）。
- **性能层**——**跨 MSS 分段**：`segmentByMSS`（`:838`，MSS 缺省 1460，`synOptions` 声明）+ `emitData`（`:703`）逐段发 PSH-ACK 并推进 seq。**实测**：`vnc_t1_smoke_ref` 帧 26 `tcp.len=1024`、帧 28 `tcp.len=930`，**均在单 MSS 内**（1024/930 < 1460）→ **存量 21 例无一触发分段**（G-VNC-4）。最小/最大边界帧：最小 = Bell（1B，`tcp.len=1`）+ ClientInit（1B）+ 版本（12B）；最大 = FBU（`tcp.len=1024`，缺省 initial_fbu 全屏 hextile 1024×768 时**约 2190 帧/3.3MB**，用例注释明确回避）。字段长度上界：width/height u16 ≤ 65535（`Validate` 拒越界）；nameLen u32 无上界守卫（G-VNC-13）。多流并发：由策略级 `flow_control` 承载（本版 21 例未用，§14 G-VNC-12）。
- **数据场景层**——正常值/边界值/非法值三类逐项见 §10.3 变体表（27 行）。
- **地址与流层**——**IPv4 已覆**（21/21）；**IPv6 今日零用例**（`EtherTypeFor(spec.SrcIP)` 与 `L3Base` 支持，单测 `TestIPv6Hosts` 覆盖，但**无 pcap 用例**）→ **A′ 立项 G-VNC-1**；**单流基线**已覆（21/21）；**流关联（控制流派生数据流）显式不适用**——VNC 是单一 TCP 连接承载全部消息，无副连接；**多流（会话内并发流）显式不适用**——单连接串行收发，多流由策略级 `flow_control` 承载（本版未用）。
- **业务层**——十六场景全部有落点（上表）；**多会话显式不适用**——`VNCConfig` **无 `Sessions` 字段**（机读实测，`types.go:9023-9137`），协议层是单连接单会话；多连接由 `flow_control` 的多流承载（G-VNC-12）。

**次要合法行为显式不适用声明（不设正例、亦不得进负例）**：① Tight/ZRLE/CoRRE/RRE/CopyRect 编码**数据**（未实现，§1 边界 1/4）；② 真实 DES 加密与密码学验证（未实现，§1 边界 2）；③ 按键/鼠标真实语义（无状态机，§1 边界 3）；④ 像素格式自适应（硬编码 4B/像素，G-VNC-7）；⑤ 安全类型 0（Invalid）与其他类型（`Validate` 拒，G-VNC-3）；⑥ RST 异常中断（框架 TCP 能力，本层零断言，G-VNC-14）。

## 5. 消息/事务模型与状态机

**事务定义**：一次请求 + 一次响应。本协议是**双向异步消息流**而非严格请求-响应：握手阶段是**严格交替**（server→client→server→…），数据面是**客户端驱动**（客户端发 PointerEvent/FBU 请求，服务端答 FBU），**无关联标识**（RFB 无 transactionId；关联靠**顺序**与**语义位置**）。

**多事务**：一个连接内按序执行——T-12（rounds=2 × interval=2 → 2 轮 ×（1 PointerEvent + 2 FBU））、T-9（extras 交织于每个 FBU 前）、T-1（1 轮）。

### 5.1 状态机（RFC 6143 §7.1 协议状态）

| 状态 | 进入条件 | 合法事件 | 产出 | 非法转移 |
|---|---|---|---|---|
| **S0 ProtocolVersion** | TCP 建连 | 服务端发 H1；客户端回 H2 | 12B ×2 | 客户端先发（RFC：服务端先讲）——本实现**恒服务端先发**（`Plan:726` `down(versionString)` 先于 `:727` `up`） |
| **S1 Security** | H1/H2 完成 | 服务端发 H3；客户端选 H4 | H3 + H4 | 客户端选**未列出的类型**——本实现**不校验**（客户端回显 `cfg.SecurityType`，而 H3 由同一值决定，恒自洽，G-VNC-3） |
| **S1a Tight 三段** | S1 选 16 | H5 TunnelCaps → H6 AuthCaps → H7 选认证类型 | 3 条 | — |
| **S2 Auth** | S1（选 2 或 16） | 服务端 H8 挑战；客户端 H9 应答；服务端 H10 结果 | 3 条 | 客户端跳过应答直发结果——本实现恒按序产出 |
| **S3 Init** | H10 result == 0 | 客户端 ClientInit；服务端 ServerInit（+Tight InteractionCaps） | 2 或 3 条 | **H10 != 0 时禁止进入 S3**——本实现 `Plan:741-750` **立即拆链 return**（无 ClientInit/ServerInit）✓ |
| **S4 Normal** | S3 完成 | 客户端 C1/C2/C3/C4/C5/C6；服务端 S1/S2/S3/S4 | 按配置 | **跳过认证直接发消息**：本实现无此路径（消息面在 S3 之后无条件产出，无状态门） |
| **S5 Closed** | FIN 四包 | — | — | — |

**确定性**：同一配置必然产出同一字节序列（**唯一例外**：`InitialSeq == 0` 时 `clientSeq = randomUint32()`、`serverSeq = randomUint32()`、`ipID = randomIPID()`——见 `vnc.go:657-662`/`:639`。这些是 TCP/IP 序号与 IP-ID，**不影响应用层载荷字节**，故所有 frame/field 断言仍确定；`packet_count` 亦确定）。禁止随机/未定义行为——本实现应用层无随机。

**生成器在合法/非法状态下的行为**：`Validate` 失败 → `Plan` 返回 error（`:554-556`）→ 任务失败、**零包**（§7）；`Validate` 通过 → 按固定剧本产出，**无运行时状态分支**（除 `AuthResult != 0` 与各 `nil`/布尔开关）。

### 5.2 完整事件序（`Plan`，`vnc.go:553-820`）

```
TCP: SYN(up) → SYN-ACK(down) → ACK(up)                       [3]
H1: down versionString                                        [1]
H2: up   versionString                                        [1]
H3: down secTypesBytes(secType)                               [1]
H4: up   {byte(secType)}                                      [1]
若 secType == 16 (Tight):
  H5: down {0,0,0,0}                                          [1]
  H6: down buildAuthCaps()                                    [1]
  H7: up   {0,0,0,2}                                          [1]
若 secType ∈ {16, 2}:
  H8: down challenge                                          [1]
  H9: up   response                                           [1]
H10: down buildSecurityResult(AuthResult, AuthReason)         [1]
若 AuthResult != 0: FIN-ACK(up)/ACK(down)/FIN-ACK(down)/ACK(up) [4] → return
ClientInit: up {0x01 | 0x00}                                  [1]
ServerInit: down buildServerInit(...)                         [1]
若 secType == 16: InteractionCaps: down buildInteractionCaps() [1]
若 sendPixelFormat:  C1 up buildSetPixelFormat()              [1]
若 sendEncodings:    C2 up buildSetEncodings()                [1]
每 keyEvents:        C4 up buildKeyEvent()                    [n]
C3: up buildFBURequest(false, width, height)                  [1]
若 ClientCutText != "": C6 up buildClientCutText()            [1]
extras → S1 initial FBU: down buildFramebufferUpdate(initialFBU) [1]
每 round r ∈ [0, rounds):
  C5: up buildPointerEvent()                                  [1]
  每 i ∈ [0, fbuInterval):
    extras → S1: down buildFramebufferUpdate(updateRects)      [1]
C3: up buildFBURequest(true, width, height)                   [1]
TCP: FIN-ACK(up)/ACK(down)/FIN-ACK(down)/ACK(up)              [4]
```

**实测帧位（`vnc_t1_smoke_ref`，33 帧）**：f1 SYN / f2 SYN-ACK / f3 ACK / f4 版本 / f5 版本 / f6 secTypes / f7 选 16 / f8 TunnelCaps / f9 AuthCaps / f10 选认证 / f11 挑战 / f12 应答 / f13 结果 / f14 ClientInit / f15 ServerInit / f16 InteractionCaps / f17 SetPixelFormat / f18 SetEncodings / f19–24 KeyEvent×6 / f25 FBU 请求（非增量）/ f26 initial FBU / f27 PointerEvent / f28 FBU / f29 增量 FBU 请求 / f30–33 FIN 四包。**与上序逐帧一致**。

### 5.3 包数公式（实测校准，§9 全 17 正例验证）

```
帧数 = 3（TCP 握手）
     + H（握手消息数）
     + C（客户端消息数）
     + (1 + R × I)（FBU 总数）
     + R（PointerEvent 数）
     + E（extras 总数）
     + 1（收尾增量 FBU 请求）
     + 4（TCP 拆链）

H = Tight(16): 13 = 2(版本) + 2(secTypes) + 5(TunnelCaps+AuthCaps+选认证+挑战+应答) + 1(结果) + 1(ClientInit) + 1(ServerInit) + 1(InteractionCaps)
    VNC Auth(2): 9 = 2 + 2 + 2(挑战+应答) + 1(结果) + 1(ClientInit) + 1(ServerInit)
    None(1):     7 = 2 + 2 + 0 + 1 + 1 + 1
    认证失败（H 随安全路径而变，**且 C/R/E/收尾项全为 0**）:
      Tight + AuthResult!=0: H = 10 = 2 + 2 + 5 + 1（无 ClientInit/ServerInit/InteractionCaps）
      VNC Auth + AuthResult!=0: H = 7 = 2 + 2 + 2 + 1
      None + AuthResult!=0: H = 5 = 2 + 2 + 0 + 1
C = [setPixelFormat?1] + [setEncodings?1] + len(keyEvents) + 1（非增量 FBU 请求）+ [clientCutText?1]
R = rounds，I = fbu_update_interval
E = (1 + R×I) × ([bell?1] + [colourmap?1] + [serverCutText?1])
```

**17 正例逐例验证**（§9 表；与实测 pcap 帧数 **17/17 一致**）：

| 用例 | H | C | R×I | E | 计算 | 实测 |
|---|---:|---:|---:|---:|---:|---:|
| T-1/T-2/T-6/T-7/T-13/T-18/T-19/T-20/T-21 | 13 | 9 | 1×1 | 0 | 3+13+9+2+1+0+1+4 | **33** ✓ |
| T-3（sec=2） | 9 | 9 | 1 | 0 | 3+9+9+2+1+0+1+4 | **29** ✓ |
| T-4（sec=1） | 7 | 9 | 1 | 0 | 3+7+9+2+1+0+1+4 | **27** ✓ |
| T-5（认证失败） | 10 | 0 | 0 | 0 | 3+10+0+0+0+0+0+4 | **17** ✓ |
| T-8（1 按键） | 13 | 4 | 1 | 0 | 3+13+4+2+1+0+1+4 | **28** ✓ |
| T-9（Bell+2 CutText） | 13 | 10 | 1 | 4 | 3+13+10+2+1+4+1+4 | **38** ✓ |
| T-10（colourmap） | 13 | 9 | 1 | 2 | 3+13+9+2+1+2+1+4 | **35** ✓ |
| T-11（pf+enc 关） | 13 | 7 | 1 | 0 | 3+13+7+2+1+0+1+4 | **31** ✓ |
| T-12（R=2,I=2） | 13 | 9 | 2×2 | 0 | 3+13+9+5+2+0+1+4 | **37** ✓ |

## 6. 性能设计与验收（CORE_MEMORY §6.1–6.8）

- **目标与边界**：单流全链 17–38 帧（存量范围，含握手与拆链）；**缺省全屏 hextile（1024×768）单帧约 3.3MB / 全会话约 2190 帧**——存量用例**全部用小矩形**（`initial_fbu` 12×19、`update_rects` 12×19）以适配冒烟断言（用例注释明写）。MSS 缺省 1460（`DefaultMSS`，`:48`；`synOptions` 在 SYN 帧声明 MSS + Window Scale 7 + SACK-Permitted）。
- **分段规则（RFC 879）**：`segmentByMSS(payload, mss)`（`:838`）按 MSS 切块，**段数 = ceil(len/mss)**（空 payload 产 1 个空块）；`emitData`（`:703`）逐段发 **PSH-ACK** 并推进 `senderSeq += len(seg)`。**实测**：`vnc_t1_smoke_ref` 帧 26 `tcp.len=1024`、帧 28 `tcp.len=930`——**均 < MSS 1460，存量零分段证据**（G-VNC-4）。触发分段所需最小配置：raw 矩形 `w×h×4 + 12 > 1460`，即 `w×h > 362`（如 20×19）。
- **长度核算（须写清，逐项可复算）**：
  - 最小帧：**Bell 1B**（`tcp.len=1`，实测 T-9 帧 27）；ClientInit 1B；ProtocolVersion 12B。
  - ServerInit：**24 + nameLen**——缺省 nameLen 14 → **38B**（实测 T-1 帧 15 `tcp.len=38`）；T-18 nameLen 5 → 29B。
  - InteractionCaps：**8 + 16n**——缺省 11 记录 → **184B**（实测 T-1 帧 16 `tcp.len=184`）；T-20 2 记录 → **40B**（实测 T-20 帧 16 `tcp.len=40`）。
  - SetEncodings：**4 + 4n**——缺省 15 项 → **64B**（实测 T-1 帧 18）；T-19 3 项 → 16B。
  - Raw FBU：`4 + 12 + w×h×4`——T-7 12×19 → `4+12+912 = 928`（实测 T-7 帧 28 `tcp.len=928`）✓。
  - Hextile FBU：`4 + Σ(12 + 瓦片数×(1 + tileW×tileH×4))`。12×19 → 瓦片网格 `ceil(12/16)×ceil(19/16) = 1×2 = 2` 瓦片，瓦片尺寸 12×16 与 12×3 → `2×(1) + 12×16×4 + 12×3×4 = 2 + 768 + 144 = 914`；全帧 `4 + (12+82) + (12+914) = 4+94+926 = 1024`（实测 T-1 帧 26 `tcp.len=1024`）✓ **与实测逐字节吻合**。
  - XCursor：**恒 82**（缺省 blob）。
- **验收两路（§6.3 强制）**：pcap（`/tmp/mcp-pcaps/vnc/`，**20/21 在案**，正例 `<id>.pcap` / 负例 `<id>.neg.pcap`）与 NIC（`enp135s0f0np0`，`nic_capture` 开关）共用同一断言集；断言实际 `vnc.*` 字段、帧原始 hex 与 `packet_count`，**不只断言"任务没报错"**——21 例中 13 例有 `fields`、18 例有 `frames`，共 **42 条 field + 36 条 frame**（§9）。
- **六类场景落点（§6.6）**：基线（T-1，33 帧）/ 目标规模（T-12 rounds×interval 线性，37 帧）/ 压力上限（T-9 extras 交织，38 帧，存量最大）/ 长时间运行（T-12 多轮承载语义）/ 并发交错（顺序多轮承载语义，并发路径为例外不启用）/ 背压（`packet_count` 精确计数守卫帧数漂移 + `segmentByMSS` 分段守卫）。

## 7. 错误处理（负例锚词表，与 testcase §4 一一对应、同序）

以下输入必须由 **registry V9 范围检查**或 **planner `Validate`** 拒绝并传播为 task error，不得产出成功 PCAP、`completed/0 packet` 或只剩 TCP 外壳的假成功（**实测 3 例在案负例 pcap 均 0 帧**，§0 #6）：

| # | 负例 ID | 故障输入 | 拒绝层 | 代码锚词（逐字） | 代码行 |
|---:|---|---|---|---|---|
| N-1 | `vnc_t14_neg_sec_type` | `security_type: 7` | planner `Validate` | `invalid vnc security type 7 (allowed: 1, 2, 16)` | `vnc.go:136` |
| N-2 | `vnc_t15_neg_auth_result` | `auth_result: 3` | **registry V9**（`Min:0,Max:2`） | `layers: layer "vnc" field "auth_result" = 3 invalid: out of range [0,2]` | `registry.go:2012` + `complete.go:325` |
| N-3 | `vnc_t16_neg_rect_encoding` | `update_rects[0].encoding: "jwt"` | planner `Validate`（`validateRect`） | `invalid vnc rect encoding "jwt" (allowed: raw, hextile, xcursor)` | `vnc.go:206` |
| N-4 | `vnc_t17_neg_width_zero` | `width: 0`（**显式 0**） | planner `Validate` | `invalid vnc width 0 (allowed: 1-65535)` | `vnc.go:142` |

**锚词口径**：`error_contains` 是**子串**判定；4 例均命中（N-2 的子串 `out of range [0,2]` 落在 V9 完整文案内）。

**N-4 的显式 0 语义（须写清）**：registry V9 对 `u == 0` **直接放行**（`complete.go:319-322` "显式 0 = 用 schema 默认值"），故 `width: 0` **过 V9**，落到 planner `Validate` 的 `< 1` 分支。这是本协议唯一一条"V9 放行、planner 拦截"的负例——**必须存在**，否则该分支零覆盖。

**负例原子性**：每例单一故障注入；单次执行不得混注。4 例均为单键注入，**无并存注入**（与 opcua 存量 N-1 的两注入并存不同）。

**未入用例的拒绝分支（A′ 立项，不得冒充已覆盖）**——`Validate` + `validateRect` 共 **21 条** `fmt.Errorf` 拒绝分支（`vnc.go:119-220` 逐条机读，锚词逐字），今日覆盖 **3 条**（#4 sec_type / #19 rect encoding / #6 width），**18 条零覆盖**：

| # | 锚词（逐字） | 行 | # | 锚词（逐字） | 行 |
|---:|---|---:|---:|---|---:|
| 1 | `invalid source IP: %s` | `:122` | 12 | `invalid vnc fbu update interval %d` | `:160` |
| 2 | `invalid destination IP: %s` | `:127` | 13 | `invalid vnc pixel format bpp %d (allowed: 8, 16, 32)` | `:164` |
| 3 | `vnc config is required` | `:131` | 14 | `invalid vnc pixel format depth %d (allowed: 1-%d)` | `:167` |
| 4 | `invalid vnc security type %d (allowed: 1, 2, 16)` | `:136` | 15 | `invalid vnc key %d` | `:172` |
| 5 | `invalid vnc auth result %d (allowed: 0, 1, 2)` | `:139` | 16 | `invalid vnc encoding %d` | `:177` |
| 6 | `invalid vnc width %d (allowed: 1-65535)` | `:142` | 17 | `invalid vnc colour %q` | `:193` |
| 7 | `invalid vnc height %d (allowed: 1-65535)` | `:145` | 18 | `invalid vnc rect %d %d %d %d` | `:203` |
| 8 | `invalid vnc rounds %d` | `:148` | 19 | `invalid vnc rect encoding %q (allowed: raw, hextile, xcursor)` | `:206` |
| 9 | `invalid vnc pointer x %d (allowed: 0-65535)` | `:151` | 20 | `invalid vnc xcursor blob %q` | `:211` |
| 10 | `invalid vnc pointer y %d (allowed: 0-65535)` | `:154` | 21 | `invalid vnc hextile data %q` | `:216` |
| 11 | `invalid vnc pointer button %d (allowed: 0-255)` | `:157` | | | |

**覆盖统计**：21 条 = 已覆 **3**（#4/#6/#19）+ 零覆盖 **18**（其余全部）→ A′ 立项 G-VNC-3。
**可达性诚实声明**：#5（`auth result`）经层链**不可达**——V9 的 `Min:0,Max:2` 先于 planner 拦截（N-2 即走 V9）；仅引擎直调绕过 V9 时可命中。其余 17 条零覆盖分支**均可经层链到达**（对应 registry 字段或列表内部，V9 不下探列表——`key_events`/`encodings`/`initial_fbu`/`update_rects` 的 `Type: "list"` 无范围，故 #15/#16/#17/#18/#20/#21 全部可达）。

**不得误报的合法协议事件**：认证失败分支（T-5，**合法**：SecurityResult 1 + 提前拆链）；`share_desktop=false`（T-6）；`client_set_pixel_format=false` / `client_set_encodings=false`（T-11）；`bell=true` / 非空 cut text / colourmap（T-9/T-10）；自定义 `interaction_caps`（T-20）；`challenge_seed`/`response_seed` 非 0（T-21）；`rounds>1` / `fbu_update_interval>1`（T-12）。

## 8. 边界

- **帧长**：最小 **1B**（Bell / ClientInit）；ServerInit 24+nameLen（缺省 38）；InteractionCaps 8+16n（缺省 184）；SetEncodings 4+4n（缺省 64）；FBU 4+Σrect（Raw 12+w×h×4 / Hextile 瓦片式 / XCursor 82）。
- **分段**：`segmentByMSS` 按 MSS（缺省 1460）切块，**存量零分段**（最大实测 `tcp.len=1024`）→ G-VNC-4。
- **安全类型**：只接受 `1`/`2`/`16`（`Validate:135`）；**0（Invalid）与其他值拒绝**。`security_type` 在 registry **不带范围**（枚举由 planner 拦，registry 注释明写"V9 区间会误伤"）。
- **auth_result**：`0`/`1`/`2`（V9 `Min:0,Max:2`）；`1` 与 `2` 走**同一失败分支**（`Plan:741` 只判 `!= 0`）——`auth_result=2` 今日零用例（G-VNC-3）。
- **width/height**：`1–65535`（u16 满值域）；**显式 0 被 planner 拒**（N-4）。
- **rounds / fbu_update_interval**：`≥ 1`（V9 `Min:1,Max:1000000`）；**显式 0 被 planner 拒**（`getIntPresence` 保留 0）→ 零用例（G-VNC-3）。
- **pointer_x/pointer_y**：`0–65535`；**pointer_button**：`0–255`。
- **encodings**：**registry 不带范围**（含负值伪编码 `-240`/`-239`/`-232`/`-250`/`-26`/`-224`/`-223`）；planner `Validate` 限 `-256 ≤ e ≤ 0x7FFFFFFF`（`:176`）——**注意 `-256` 下界与 i32 上界不对齐**（i32 最小值 `-2147483648` 会被拒）→ G-VNC-13。
- **rect**：`x/y ∈ 0–65535`、`width/height ∈ 1–65535`；**不校验 `x+width ≤ framebuffer-width`**（RFC 6143 §9.1 要求矩形在帧缓冲内）→ G-VNC-10。
- **pixel_format**：`bpp ∈ {8,16,32}`、`1 ≤ depth ≤ bpp`；**raw/hextile 像素宽度硬编码 4B**（不随 bpp 变）→ G-VNC-7。
- **key**：planner 限 `0 ≤ key ≤ 0xFFFFFFFF`（`:171`，i32 解析后恒成立，**实际不可达**）→ G-VNC-3。
- **端口**：缺省 5900（双缺省，§2）；**21 例全部依赖缺省**，非缺省端口（5901–5909）零用例 → G-VNC-12。
- **地址族**：存量全 IPv4；**IPv6 零用例**（单测有、pcap 无）→ G-VNC-1。
- **多会话**：`VNCConfig` 无 `Sessions` 字段 → **协议层显式不适用**；多连接走 `flow_control`（零用例）→ G-VNC-12。
- 不得产生回绕长度或超量分配（帧长由各 `build*` 一次算定，无两遍编码）。

## 9. 原子 ID 与完成定义（21 个唯一语义 ID，顺序为权威）

**顺序 = `cases/vnc.json` 数组顺序**（机读实测，非 T 编号顺序）。

| # | ID | 类型 | 覆盖（设计 §） | packet_count | field | frame |
|---:|---|---|---|---:|---:|---:|
| 1 | `vnc_t1_smoke_ref` | 正 | §3.1–§3.6 全链冒烟（Tight 13 消息 + 消息面 + FBU 循环 + 拆链） | **33** | 23 | 4 |
| 2 | `vnc_t2_handshake_bytes` | 正 | §3.1/§3.2：握手 13 消息逐字节钉 | **33** | 0 | 12 |
| 3 | `vnc_t3_sec_type_vncauth` | 正 | §3.1：VNC Auth 路径（无 caps 三段） | **29** | 3 | 2 |
| 4 | `vnc_t4_sec_type_none` | 正 | §3.1：None 路径（无挑战/应答） | **27** | 2 | 2 |
| 5 | `vnc_t5_auth_fail` | 正 | §3.1 H10 失败分支：reason 透传 + 无 ServerInit + 提前拆链 | **17** | 1 | 2 |
| 6 | `vnc_t6_share_false` | 正 | §3.2：ClientInit shared-flag=0 | **33** | 1 | 1 |
| 7 | `vnc_t7_raw_rect` | 正 | §3.4：Raw 编码确定性像素 | **33** | 0 | 1 |
| 8 | `vnc_t8_key_down_explicit` | 正 | §3.5 C4：KeyEvent 显式单键 down | **28** | 0 | 1 |
| 9 | `vnc_t9_extras_mix` | 正 | §3.7：Bell + ServerCutText + ClientCutText 三消息交织 | **38** | 2 | 3 |
| 10 | `vnc_t10_colourmap` | 正 | §3.6 S2：SetColourMapEntries | **35** | 1 | 1 |
| 11 | `vnc_t11_client_msgs_off` | 正 | §3.5 C1/C2 关闭 | **31** | 1 | 0 |
| 12 | `vnc_t12_rounds_linear` | 正 | §5：rounds=2 × interval=2 线性编排 | **37** | 3 | 0 |
| 13 | `vnc_t13_pointer_default` | 正 | §3.5 C5：PointerEvent 缺省坐标 507/320 | **33** | 1 | 1 |
| 14 | `vnc_t14_neg_sec_type` | **负** | §7 N-1：`security_type=7` | —（0 帧） | 0 | 0 |
| 15 | `vnc_t15_neg_auth_result` | **负** | §7 N-2：`auth_result=3`（V9 区间） | —（0 帧） | 0 | 0 |
| 16 | `vnc_t16_neg_rect_encoding` | **负** | §7 N-3：rect `encoding="jwt"` | —（0 帧） | 0 | 0 |
| 17 | `vnc_t17_neg_width_zero` | **负** | §7 N-4：`width=0`（显式 0 过 V9） | —（0 帧） | 0 | 0 |
| 18 | `vnc_t18_init_customize` | 正 | §3.2/§3.3：ServerInit 定制（name/w/h/pixel_format） | **33** | 3 | 1 |
| 19 | `vnc_t19_encodings_pointer` | 正 | §3.5 C2/C5：SetEncodings 显式列表 + PointerEvent 显式坐标 | **33** | 1 | 2 |
| 20 | `vnc_t20_caps_customize` | 正 | §3.2：InteractionCaps 定制（头 + 2 记录） | **33** | 0 | 1 |
| 21 | `vnc_t21_seeds` | 正 | §3.1 H8/H9：challenge/response seed 确定性字节 | **33** | 0 | 2 |

**统计（机读实测）**：21 例 = **17 正 + 4 负**；`packet_count` 出现 **17** 次（正例全有，负例全无）；`fields` 断言 **42** 条（分布在 **13 例**：T-1=23 / T-2=0 / T-3=3 / T-4=2 / T-5=1 / T-6=1 / T-7=0 / T-8=0 / T-9=2 / T-10=1 / T-11=1 / T-12=3 / T-13=1 / T-18=3 / T-19=1 / T-20=0 / T-21=0；**15 个不同 field 名**）；`frames` 断言 **36** 条（分布在 **18 例**，**全部 offset 54**）；`expect` 键集合 4 种（见 testcase §1）。

**17 正例帧数 17/17 与实测 pcap 一致**（§0 #6）；**4 负例中 3 例 pcap 在案且均 0 帧**，第 4 例（`vnc_t15_neg_auth_result`）pcap **未留档**（G-VNC-2）。

**可用但未收编的 tshark 字段（本轮实测，A′ 候选，G-VNC-20）**：今日 21 例只用 **15 个不同 field 名**（机读实测）。以下字段**已实测可用**却零使用——每条均已在本轮用 pcap 探针验证过取值：

| 字段 | 类型 | 实测取值（用例/帧） |
|---|---|---|
| `vnc.key_down` | BOOLEAN | T-8 帧 19 = `1`；T-1 帧 19–24 全 `0`（**存量 T-8 的 `notes` 称"tshark 不出 key_down 字段"——本轮实测该字段存在且输出 `1`，该 notes 文案与事实相反**，G-VNC-20） |
| `vnc.key` | UINT32 HEX | T-8 帧 19 = `0x0000ffe9`；T-1 帧 19–24 = `0x0000ffe9/ffe3/ffe1/ffea/ffe4/ffe2`（**逐条对上缺省 6 键**） |
| `vnc.pointer_x_pos` / `vnc.pointer_y_pos` | UINT16 | T-13 帧 27 = `507` / `320`；T-19 帧 27 = `100` / `200` |
| `vnc.button_1_pos` … `vnc.button_8_pos` | BOOLEAN | T-19 帧 27 `button_1_pos=1`（`pointer_button=1`）；T-13 帧 27 全 `0` |
| `vnc.client_set_encodings_num` | UINT16 | T-19 帧 18 = `3`（显式 3 项）；T-1 帧 18 = `15`（缺省） |
| `vnc.client_set_encodings_encoding_type` | INT32 | T-19 帧 18 = `0,5,-240`（**逐项对上显式列表**） |
| `vnc.fb_update_num_rects` | UINT16 | 已用（T-1 帧 26 = `2`） |
| `vnc.fb_update_encoding_type` | INT32 | T-1 帧 26 = `-240,5`（**两 rect 编码逐项**） |
| `vnc.fb_update_width` / `vnc.fb_update_height` | UINT16 | T-1 帧 26 = `12,12` / `19,19` |
| `vnc.fb_update_x_pos` / `vnc.fb_update_y_pos` | UINT16 | 同上 rect 坐标 |
| `vnc.colormap_first_color` | UINT16 | T-10 帧 26 = `0` |
| `vnc.client_cut_text` / `vnc.server_cut_text` | STRING | T-9 帧 26 = `cp` / 帧 28 = `brd` |
| `vnc.encoding_name` / `vnc.encoding_vendor` | STRING | InteractionCaps 记录名/厂商（T-1 帧 16、T-20 帧 16） |
| `vnc.hextile_subencoding` / `vnc.hextile_num_subrects` | UINT8 | Hextile 瓦片子编码（T-1 帧 26/28） |

> **注**：`vnc.bell`、`vnc.pointer_x`、`vnc.pointer_y`、`vnc.button_mask`、`vnc.fb_update_rect_width`、`vnc.fb_update_rect_x` **不在** tshark 3.6.14 字段表（实测 0 命中）——**字段名以 `tshark -G fields` 实测为准**（本版已逐名核对，G-VNC-20 口径：不得臆造字段名）。

## 10. P1 规范矩阵（CORE_MEMORY §4 八项：规范要求→业务场景→代码现状→缺口）

### 10.1 八项规范矩阵

| # | 八项 | 规范要求 | 业务场景 | 代码现状 | 缺口 |
|---|---|---|---|---|---|
| 1 | 连接模型 | TCP 客户端主动建连；**服务端先发 ProtocolVersion**（RFC 6143 §7.1.1） | 场景①–⑯ | `DependsOn ["ip"]` 单值（`registry.go:2009`）；TCP 握手/拆链自建（`vnc.go:719`/`:811`）；服务端先发（`Plan:726` 先于 `:727`）✓ | 无 |
| 2 | 命令/消息表 | 握手 10 类 + 客户端 6 类 + 服务端 4 类（RFC 6143 §7–§9） | 场景①–⑯ | `secTypesBytes`/`buildAuthCaps`/`buildSecurityResult`/`buildServerInit` + 6 客户端 builder + 4 服务端 builder（§11.1） | 无（Tight 三 caps 属扩展，§0 #2 已声明） |
| 3 | 状态机 | S0 版本 → S1 安全 → S2 认证 → S3 初始化 → S4 正常 → S5 关闭（§5.1） | T-1/T-3/T-4/T-5 | 无显式状态变量，**由 `Plan` 顺序结构隐式实现**；认证失败早退（`Plan:741`）✓ | 无（"客户端选未列出类型"不校验 → G-VNC-3） |
| 4 | 字段表 | PIXEL_FORMAT 10 字段 + 各消息逐字段（§3.3–§3.6） | 数据场景层 | 逐 `build*` 函数按偏移写（§3） | `red_max` 等 5 字段 0→缺省不可表达 → G-VNC-10 |
| 5 | 错误处理 | 4 类负例 + 18 条未入例拒绝分支（§7） | 负例 N-1…N-4 | `Validate` **21 条**拒绝分支（`vnc.go:119-220`）+ registry V9 范围（26 键中 8 键带范围） | A′ 18 条（§14 G-VNC-3） |
| 6 | 超时与活性 | **RFB 无保活/心跳机制**（RFC 6143 无 PING 类消息）；长会话靠客户端周期发 FBU 请求 | T-12 | 无 keepalive 代码（如实）；`rounds`/`fbu_update_interval` 承载"多轮刷新"语义 | **显式不适用**（协议无心跳）——**不得硬凑保活用例** |
| 7 | NAT/代理/被动 | **无被动/主动模式概念**（VNC 是客户端直连单一 TCP 连接） | — | 无 `sessions[]`、无 `driven_by` | **显式不适用**被动模式；NAT 穿透为框架面 |
| 8 | 版本/方言 | 协议版本 `RFB 003.008` 唯一；Tight 为 TightVNC 扩展 | 正例 17 | `versionString` 恒 `RFB 003.008\n`（`:54`，**不可配**）；`security_type` 三值（`:135`） | 版本协商降级（`003.003`/`003.007`）**未实现** → G-VNC-15 |

### 10.2 子表①：消息 × 终态矩阵（逐格已覆/立项/不适用）

| 消息 | T1 正常终态 | T2 配置拒绝 | T3 RST 异常终态 |
|---|---|---|---|
| ProtocolVersion | 已覆（T-1/T-2） | 已覆（N-1 代表例，拒绝与消息无关） | A′ 立项（G-VNC-14） |
| SecurityTypes | 已覆（T-2/T-3/T-4） | 同上代表已覆 | A′ 立项（G-VNC-14） |
| TunnelCaps | 已覆（T-2） | 同上代表已覆 | A′ 立项（G-VNC-14） |
| AuthCaps | 已覆（T-2） | 同上代表已覆 | A′ 立项（G-VNC-14） |
| AuthChallenge/Response | 已覆（T-2/T-21） | 同上代表已覆 | A′ 立项（G-VNC-14） |
| SecurityResult | 已覆（T-2 成功 / T-5 失败） | 同上代表已覆 | A′ 立项（G-VNC-14） |
| ClientInit | 已覆（T-1=1 / T-6=0） | 同上代表已覆 | A′ 立项（G-VNC-14） |
| ServerInit | 已覆（T-1 缺省 / T-18 定制） | 同上代表已覆 | A′ 立项（G-VNC-14） |
| InteractionCaps | 已覆（T-1 缺省 / T-20 定制） | 同上代表已覆 | A′ 立项（G-VNC-14） |
| SetPixelFormat | 已覆（T-1 发 / T-11 关） | 同上代表已覆 | A′ 立项（G-VNC-14） |
| SetEncodings | 已覆（T-1 缺省 / T-19 显式） | 同上代表已覆 | A′ 立项（G-VNC-14） |
| KeyEvent | 已覆（T-1 缺省 6 / T-8 显式 1） | 同上代表已覆 | A′ 立项（G-VNC-14） |
| FBURequest | 已覆（T-1 非增量 + 增量 / T-13） | 同上代表已覆 | A′ 立项（G-VNC-14） |
| PointerEvent | 已覆（T-13 缺省 / T-19 显式） | 同上代表已覆 | A′ 立项（G-VNC-14） |
| ClientCutText | 已覆（T-9） | 同上代表已覆 | A′ 立项（G-VNC-14） |
| FramebufferUpdate | 已覆（T-1/T-7/T-9/T-10/T-12） | 同上代表已覆 | A′ 立项（G-VNC-14） |
| SetColourMapEntries | 已覆（T-10） | 同上代表已覆 | A′ 立项（G-VNC-14） |
| Bell | 已覆（T-9） | 同上代表已覆 | A′ 立项（G-VNC-14） |
| ServerCutText | 已覆（T-9） | 同上代表已覆 | A′ 立项（G-VNC-14） |

**逐格重数**：19 行 × 3 列 = 57 格——已覆 **38**（T1 列 19 + T2 列 19）/ A′ 立项 **19**（T3 列 19）/ 不适用 **0**，零空格。38 + 19 + 0 = 57 ✓

### 10.3 子表②：数据形态变体表（协议相关全部形态逐项）

共 **27 行**，每行均有正例/负例落点或立项/不适用结论：

| # | 变体 | 落点 |
|---:|---|---|
| 1 | `security_type=16`（缺省） | 覆（T-1/T-2/T-5/T-6…T-21 除 T-3/T-4） |
| 2 | `security_type=2` | 覆（T-3） |
| 3 | `security_type=1` | 覆（T-4） |
| 4 | `security_type` 非法（0/3/7/17） | 覆（N-1 取 7；**0/3/17 未取值**，同分支已覆） |
| 5 | `auth_result=0`（成功） | 覆（全正例除 T-5） |
| 6 | `auth_result=1` + reason | 覆（T-5，reason `"denied"` 6B） |
| 7 | `auth_result=2`（同失败分支） | **A′ 立项**（`Plan:741` 只判 `!=0`，分支同 T-5，但取值未覆盖） |
| 8 | `auth_result` 越界（3） | 覆（N-2，V9 拦） |
| 9 | `auth_reason` 非空且 `auth_result=0` | **A′ 立项**（`buildSecurityResult:324` 只在 `!=0` 时追加，reason 被静默丢弃——合法但零证据） |
| 10 | `share_desktop` 缺省（true） | 覆（T-1 等） |
| 11 | `share_desktop=false` | 覆（T-6） |
| 12 | `width`/`height` 缺省（1024/768） | 覆（T-1 等） |
| 13 | `width`/`height` 定制（320/240） | 覆（T-18） |
| 14 | `width=0` 显式 | 覆（N-4） |
| 15 | `width`/`height` 满值（65535） | **A′ 立项**（上界零证据） |
| 16 | `server_name` 缺省（`QTMS:1 (ykaul)`） | 覆（T-1，nameLen 14） |
| 17 | `server_name` 定制（`SRV-X`） | 覆（T-18，nameLen 5） |
| 18 | `pixel_format` 缺省（32/24/LE/TC/255/16,8,0） | 覆（T-1，ServerInit 38B） |
| 19 | `pixel_format.bits_per_pixel=16` + `depth=16` | 覆（T-18） |
| 20 | `pixel_format` 其余 8 子键（big_endian/true_color/red_max/green_max/blue_max/red_shift/green_shift/blue_shift） | **A′ 立项**（T-18 只用 2 子键；其余零证据，且 5 键 0→缺省不可表达 G-VNC-10） |
| 21 | `interaction_caps` 缺省（0/11/0 + 11 记录，184B） | 覆（T-1/T-2 帧 16） |
| 22 | `interaction_caps` 定制（0/2/0 + 2 记录，40B） | 覆（T-20） |
| 23 | `key_events` 缺省（6 条全释放） | 覆（T-1 帧 19–24） |
| 24 | `key_events` 显式单键 down | 覆（T-8） |
| 25 | `key_events: []` 显式空 | **A′ 立项**（`parseVNCConfig:5795` 产空 slice → `Plan:599-602` 的 `== nil` 判断**不触发**，故空数组=零按键；合法但零证据） |
| 26 | `encodings` 缺省（15 项，64B） | 覆（T-1/T-2） |
| 27 | `encodings` 显式 3 项 | 覆（T-19） |

**18 覆 + 6 立项 = 24**。**注**：上表另需补 4 行以覆盖 rect 子键与端口（原表遗漏，本版补齐）：

| # | 变体 | 落点 |
|---:|---|---|
| 28 | rect `encoding="raw"` / `"hextile"` / `"xcursor"` | 覆（T-7 raw；T-1/T-12 hextile；T-1 initial_fbu xcursor） |
| 29 | rect `hextile_tile_data` / `xcursor_blob` 定制 | **A′ 立项**（两子键**零用例**，机读实测 rect 只用 5 键 → G-VNC-5） |
| 30 | `dst_port` 缺省 5900 | 覆（**21/21 例全未显式写端口**，依赖双缺省） |
| 31 | `dst_port` 非缺省（5901–5909） | **A′ 立项**（零用例 → G-VNC-12） |

**全表重数（31 行，逐行机读）**：**覆 24**（行 1,2,3,4,5,6,8,10,11,12,13,14,16,17,18,19,21,22,23,24,26,27,28,30）+ **A′ 立项 7**（行 7,9,15,20,25,29,31）= **31**，零空格，无不适用行。24 + 7 = 31 ✓

### 10.4 子表③：商业行为→用例映射表

| # | 商业行为（出处） | 用例映射 | 结论 |
|---:|---|---|---|
| 1 | 标准 Tight 会话建立（现网主流 TightVNC/RealVNC） | T-1/T-2 | 已覆 |
| 2 | 传统 VNC Auth 会话（老服务器兼容） | T-3 | 已覆 |
| 3 | 无认证内网会话 | T-4 | 已覆 |
| 4 | 认证失败拒绝 | T-5 | 已覆 |
| 5 | 独占桌面会话 | T-6 | 已覆 |
| 6 | 屏幕推送（Raw 无损） | T-7 | 已覆 |
| 7 | 键盘注入（远程操作/自动化） | T-8 | 已覆 |
| 8 | 剪贴板同步 | T-9 | 已覆 |
| 9 | 响铃通知 | T-9 | 已覆 |
| 10 | 调色板模式（8bpp 索引色服务器） | T-10 | 已覆 |
| 11 | 鼠标移动/点击 | T-13 | 已覆 |
| 12 | 长会话多轮刷新 | T-12 | 已覆 |
| 13 | 编码能力协商 | T-1/T-19 | 已覆 |
| 14 | 服务器标识识别（运维指纹） | T-1/T-18 | 已覆 |
| 15 | Tight 能力协商（扩展互操作） | T-1/T-20 | 已覆 |
| 16 | 挑战/应答脱敏（合规抓包） | T-21 | 已覆 |
| 17 | **真实 Tight/ZRLE 压缩传输** | — | **明确不解决**（§1 边界 1/4） |
| 18 | **真实 DES 加密与密码学验证** | — | **明确不解决**（§1 边界 2） |
| 19 | **协议版本降级协商（003.003/003.007）** | — | **明确不解决**（G-VNC-15） |
| 20 | **多客户端并发（同一服务器）** | — | 由 `flow_control` 承载（零用例，G-VNC-12） |
| 21 | **屏幕内容真实编码（Tight 有损/无损）** | — | **明确不解决**（§1 边界 1） |

**16 已覆 + 5 不适用（行 17–21：4 条「明确不解决」+ 1 条「由 flow_control 承载，零用例」）= 21**。✓ 无映射无确认即缺口——本表零缺口。

### 10.5 三路对照与候选方案对比

三路：①**规范原文**（RFC 6143 §7–§9 逐节 + TightVNC 扩展，定"必须是什么"——本轮已用参考 pcap 帧 4–19 逐字节对照，版本/secTypes/TunnelCaps/AuthCaps/挑战/应答/结果 七项**逐字节一致**，§0 #2）；②**商业化软件实际行为**（**部分取到**：参考 pcap 是真实 TightVNC 服务器 `QTMS:1 (ykaul)` 的会话，`tshark -Y vnc` 命中 1679 帧，提供 13 条握手消息与 FBU 结构的现网实证；但**未取到**其他实现（RealVNC/TigerVNC/libvncserver）的线字节 → G-VNC-9）；③**可靠开源实现思路**（TightVNC 的 XCursor 伪编码 -240、Interaction Caps 16B 记录布局——只借鉴"伪编码用负值 i32、caps 记录 code+vendor4+name8"两条思路）。三路一致点：握手 13 消息序列、`02 02 10` secTypes、挑战/应答各 16B、ServerInit 24+nameLen；不一致点：**XCursor 数据段的确切填充字节**（参考 pcap 含非零"垃圾"填充，实现改用零填充自建 blob，§0 #3、G-VNC-9）。

| 方案 | 走法（借鉴来源） | 取舍 | 结论 |
|---|---|---|---|
| A | **独立 `vnc` raw-IP 终结层**（本版；rtsp/pptp/xmpp 同构先例） | 三类安全路径/六类客户端消息/四类服务端消息/FBU 循环可声明可断言；TCP 自建（链上无 tcp 层）；代价 = 一套层（已落码 1679 行） | **采用** |
| B | `[ip,tcp,vnc]` 事件面层（tcp 层管握手挥手） | 需把 TCP 握手/拆链从 `Plan` 剥离为层外能力，且 raw 自驱分支需重写；21 例帧位/包数全部重钉 | **否决**（`isRawIPChain` 已按 `[ip,vnc]` 定型，`chain_planner.go:792` 名单 + `:1525` 直传；改造收益为零） |
| C | 拆成"握手层 vnc-handshake + 数据层 vnc-fbu"两层 | 两层边界（SecurityResult 结果、像素格式、编码列表）需跨层状态传递，框架层间无此通道 | **否决**（状态在 `Plan` 局部变量，单层内聚更简单） |

## 11. P2 D-VNC-1 代码设计（CORE_MEMORY §8 八要素；门1 获批 = 定稿）

> 状态说明：实现已落码（`internal/protocol/vnc/` 三文件），本 P2 条目为 as-built 文档轨对既有实现的**逆向定稿**，供门1 批准后作为后续改动的唯一入口。

### 11.1 文件清单（实测，非计划）

| 文件 | 职责 | 行数 |
|---|---|---:|
| `trafficgen/internal/core/types.go`（`:9023-9255` + `:1861`） | `VNCConfig`/`VNCPixelFormatConfig`/`VNCInteractionCapsConfig`/`VNCCapabilityConfig`/`VNCKeyEventConfig`/`VNCRectConfig`/`VNCColourMapConfig` + `FlowSpec.VNC` 槽位 | —（共享文件） |
| `trafficgen/internal/protocol/vnc/vnc.go` | 线编码：`secTypesBytes` + 4 握手 builder + 6 客户端 builder + 4 服务端 builder + `buildRect`/`rawPixels`/`hextileData` + `Validate` + `Plan`（含 TCP 自建） | **895** |
| `trafficgen/internal/protocol/vnc/layer_gen.go` | 终结层生成器（`RegisterLayerGenerator` + `RegisterLayerValidator`，`init()`） | **71** |
| `trafficgen/internal/protocol/vnc/vnc_test.go` | **25 个 `Test*`**（编码面 11 + 生成器面 9 + Validate 面 2 + 注册/默认流面 3） | **713** |
| 接线 6 件 | registry 注册（`layers/registry.go:2009`，Fields 26 键）/ translate 层内分支（`chain_planner_translate.go:2806`）/ convert 子配置搬运 + 端口缺省（`strategy_convert.go:1344`）/ protocols 准入（`protocols.go:60`）/ raw-IP 自驱名单（`chain_planner.go:792` + `:1525` + `chain_planner_util.go:54/57`）/ 扁平入口判死（`strategy_convert.go` `rawWrapChains` 表 `"vnc": "[ip,vnc]"`） | — |

**合计 1679 行**（`wc -l` 实测）。

### 11.2 接口签名

- `Validate(spec core.FlowSpec) error`（`vnc.go:119`）：IP 解析（2 分支）、`VNC == nil`、`SecurityType` 枚举、`AuthResult` 范围、width/height、`Rounds`、`PointerX/Y/Button`、`FBUUpdateInterval`、`PixelFormat` bpp/depth、每 `KeyEvent.Key`、每 `Encoding`、每 rect（`validateRect`）、colour 各 hex。**共 21 条拒绝分支**（§7）。
- `validateRect(r core.VNCRectConfig) error`（`:200`）：x/y/w/h 范围、`Encoding` 三枚举、`XCursorBlob` hex（**且 `len ≥ 6`**）、`HextileTileData` hex。
- `Plan(ctx, spec) (<-chan core.PacketConfig, error)`（`:553`）：先 `Validate`，再在**局部**补缺省（`:561-624`），goroutine 内产出全部帧（含 TCP 握手/拆链）到 `configChan`（**cap 256**，`:626`）。
- 生成器：`Name() "vnc"`；`GenEvents()` **返回 nil**（raw-IP 自驱，无事件面）；`Generate`（`layer_gen.go:28`）把 `req.Meta.VNC` 组回 `FlowSpec` 调 `NewPlanner().Plan`，逐包**把 `Direction` 改写为 `"up"`** 后 `req.Emit`（防 raw-IP drive 二次换向，`layer_gen.go:54`）。

### 11.3 数据结构

`VNCConfig{SecurityType, AuthResult, AuthReason, ShareDesktop *bool, Width, Height, ServerName, PixelFormat *VNCPixelFormatConfig, InteractionCaps *VNCInteractionCapsConfig, KeyEvents [], ClientSetPixelFormat *bool, ClientSetEncodings *bool, Encodings [], Rounds, PointerX, PointerY, PointerButton, FBUUpdateInterval, InitialFBU [], UpdateRects [], Bell, SetColourMapEntries *VNCColourMapConfig, ServerCutText, ClientCutText, ChallengeSeed, ResponseSeed}`（`types.go:9023-9137`，**26 键**，与 registry Fields **逐键一致**，机读实测）。
`VNCRectConfig{X, Y, Width, Height, Encoding, HextileTileData, XCursorBlob}`（`:9218`，**7 键**）。

### 11.4 主流程

层链配置 → `ValidateLayers`（registry Fields 26 键 allowlist + V9 范围）→ translate（`chain_planner_translate.go:2806` 层内 config → `spec.VNC`，经 `core.ParseVNCConfigFromMap` 复用扁平解析单一真相）→ `chain_planner.go:1525` `meta.VNC = spec.VNC` → raw-IP 自驱分支（`isRawIPChain` 命中）→ 生成器 `Generate` → `Planner.Plan`（`Validate` → 缺省补齐 → TCP 握手 → 握手 13 消息 → 客户端消息面 → FBU 循环 → 拆链）→ `req.Emit` 逐包（`Direction` 统一改 `"up"`）→ writer（PCAP/NIC）。

**扁平入口**：`strategy_convert.go:1344` `case "vnc"` → `parseVNCConfig` + `setDefaultDstPort(&spec, cfg, 5900)`；**顶层 `vnc` 子映射在链形状下判死**（`rawWrapChains` 表，报 `no longer accepts a top-level vnc sub-config`）。

### 11.5 错误分支

**21 条** `Validate`+`validateRect` 拒绝（`vnc.go:122-216`）+ registry V9 范围拒（26 键中 8 键带范围：`auth_result`/`width`/`height`/`rounds`/`pointer_x`/`pointer_y`/`pointer_button`/`fbu_update_interval`）+ `parseVNCConfig` 解析错（`encodings` 非数值项、`encodings` 非数组）→ 全部经 `spec.ValidationErrors` 或 `Plan` 返回 error **传 task error**（零假成功——3 例在案负例实测 0 帧）。
**静默路径（缺陷候选）**：① `buildSetColourMapEntries` 非 6 字节 hex **静默补零**（`:456-462`，G-VNC-6）；② `pixelFormatBytes` 五字段 `0 → 缺省` **静默改写**（`:269-286`，G-VNC-10）；③ `auth_reason` 在 `auth_result=0` 时**静默丢弃**（`:324`，G-VNC-3）；④ `hextileData` 的 `HextileTileData` 路径**不按 tileW/tileH 校验**，配置写错则瓦片数与尺寸不符而**无任何报错**（G-VNC-5）。

### 11.6 性能边界

见 §6（`Plan` 逐帧流式产出到 cap 256 的 channel，无全量聚合；每帧内存 = 该帧 payload；per-flow 局部状态；无跨流共享；无锁）。**唯一大内存点**：缺省 `initial_fbu` 全屏 hextile 1024×768 → 单帧约 3.3MB（`hextileData` 预分配 `(w*h*4)/16` = 196608B，实际输出约 3.3MB，**预分配容量估算偏低 16 倍**——`append` 会多次扩容，非缺陷但影响吞吐，G-VNC-16）。吞吐数字待 P4 基准，**本版不写承诺**（§6.5）。

### 11.7 与现有逻辑的冲突点

- **`CheckProtoFlat` 已有 vnc 分支**：`rawWrapChains` 表含 `"vnc": "[ip,vnc]"`（`strategy_convert.go:9096` 附近）→ 顶层 `vnc` 子映射 presence **判死**（空 map 也死）。故 **presence 负例（`{"layers":[…],"vnc":{}}`）今日可建且会真红**——与 opcua G-OPCUA-1 的"建了会真绿"相反。**本版不建该例**（存量无此例，且建例属代码/JSON 阶段动作，非文档阶段）。
- **顶层未知游离键通用门**：`CheckProtoFlat` 只查五键 + 各协议子映射白名单，**游离顶层键（如 `{layers:[…], bogus:1}`）今日不判死** → 与 moxa G-MOXA-2 / opcua G-OPCUA-1 同款框架面缺口（**不单独立项**，等框架级 unknown-key 白名单）。
- **动态 allowlist**（`internal/core/layer_dyn.go` 头部）：`vnc` **零命中**（机读实测，表内 14 个协议无 `vnc` 行）→ 层内任何业务字段出现动态对象即 `does not support dynamic`；四元组 `ip.src/dst`、`tcp.src_port/dst_port` 全开（但本协议链上无 tcp 层，端口住 spec）。见 §12.12。
- **`secTypeVNCAuthCode = 2` 与 `secTypeVNC = 2` 同值双名**（`vnc.go:32-33`）：前者用于 AuthCaps 记录的 code，后者用于安全类型枚举——**同值不同语义**，代码可读性隐患（G-VNC-17，非缺陷）。
- **`validateRect` 的 `XCursorBlob` 只校验 `len ≥ 6`**（`:210`）：RFC 要求 `6 + w*h*(bpp/8) + ceil(w/8)*h` 精确长度；实现不校验，配置写短 blob 会**静默产出长度不符的 FBU**（G-VNC-5）。

### 11.8 回滚方式

本协议文件独立成包，回滚 = revert 本协议 3 文件 + 接线 6 处（registry/protocols/translate/convert/chain_planner/chain_planner_util）；不触及其他协议。cases 回滚 = 恢复 21 例 JSON（产物文件，非文档）。

## 12. 门1 §1–§14 十四行对照表（CORE_MEMORY §15.1–15.3）

| § | 本协议怎么满足 | 证据 |
|---|---|---|
| §1 层链唯一真相 | 见 §12.1 强制展开：存量 **21/21 顶层 = `{layers}` 仅此一键，零残留**；目标形状见 §2 样例且**存量已达标**（本协议无迁移工作量） | §12.1；`cases/vnc.json` 机读实测 |
| §2 策略/任务 | 策略 = 单 vnc 流量模板；任务 = 多策略合跑 + 总量封顶；框架语义未动 | 设计 §2 样例 |
| §3 五件套 | 见 §12.3 强制展开：会话表/事务序列/关联（无派生流诚实声明）/插入位置（raw-IP 终结层）/时间线。有长连接，不豁免 | §12.3 + §5 |
| §4 查规范 | RFC 6143 §7–§9 + TightVNC 扩展 + 参考现网 pcap（`tshark -Y vnc` 1679 帧）+ tshark 3.6.14 字段表（249 字段）+ 20 例实测 pcap + 落码反推；八项矩阵 + 子表①②③ | §10 |
| §5 依赖与错误 | `DependsOn ["ip"]` 单值（`registry.go:2009`，**无 tcp 层——自建 TCP 载体**）；21 条 `Validate`+`validateRect` 拒绝 + V9 8 键范围；失败传 task error（3 例在案负例 0 帧实测） | §5/§7/§11.5 |
| §6 性能 | 见 §6（6.1–6.8 要素齐；分段规则与长度核算逐项可复算；吞吐数字标待 P4 基准，不写承诺；pcap/NIC 两路验收明写） | §6 |
| §7 三份文档 | `112-vnc-{design,testcase}.md` v1.0.0（本版，草稿层）+ D-VNC-1（§11，门1 获批 = 定稿）+ T-VNC（testcase §2，21 ID）；**无旧稿历史层**（§0） | 修订记录 |
| §8 设计先行 | 本版先于任何后续改动；门1 获批 = D-VNC-1 定稿 = 改动入口 | 提交序 |
| §9 测试三源 | 三源 = RFC 6143 + TightVNC 扩展（§10）+ D-VNC-1（§11）+ **参考现网 pcap + 20 例实测 pcap + tshark 3.6.14 字段表**（**已到抓包级**：17 正例帧数逐例一致、36 条 frame + 42 条 field 断言逐条复核全 OK、0 malformed）；21 ID 逐项回指；存量 21 例审计去向 testcase §8 | `112-vnc-testcase.md` §2/§5/§8 |
| §10 评审闭环 | 每阶段对抗自重审 + 收官隔离复审；红先绿后 | 自审日志 |
| §11 白话 | 每阶段白话一句先行（见本文首节） | 汇报 |
| §12 动态清单 | 见 §12.12 强制展开：四元组全开（allowlist 实测）；业务字段逐个列开/不开 + 理由；序号算法实读行号 | §12.12 |
| §13 schema 派生 | `vnc` 已在 `registry.go:2009` 注册（**不新增层**）；Fields **26 键**与 `VNCConfig` 26 键**逐键一致**（机读实测）；**改动 registry Fields 必须重跑 schemagen** | §11.1 |
| §14 真实流程 | suite 经 MCP 建策略建任务 → 引擎真实生成 → tshark `vnc.*` + frames 双通道 → **本车道已实跑**：20 例 pcap 在 `/tmp/mcp-pcaps/vnc/`，17 正例帧数 17/17 一致、3 负例 0 帧 | testcase §7 |

### 12.1 §1 强制展开：旧键去向 + 完整 spec_json 样例

**存量实测（逐例机读，2026-09-29）**：

| 文件 | 例数 | 顶层键分布 | 链形 | 负例 expect 形状 |
|---|---|---|---|---|
| `cases/vnc.json` | **21** | **`{layers}` ×21**（唯一顶层键，**零游离键**） | **`[ip,vnc]` ×21**（无 IPv6、无 tcp 层） | 4/4 = `{expect_error, error_contains, notes}` |

**旧键去向表（§15.3 要求"每个键写去向"）**：

| 旧键 | 存量出现例数 | 去向 |
|---|---:|---|
| `src_ip` / `dst_ip` | **0** | 本协议**从未用过顶层地址**；21/21 已住 `layers[0].ip.{src,dst}` |
| `src_port` | **0** | 本已 absent（保底 `12345`）；**本协议链上无 tcp 层**，目标形不迁端口入层（`chain_planner.go:790-792` 注释明写"层 config 无端口位，0 合法"） |
| `dst_port` | **0** | **21/21 未显式写**（依赖双缺省 5900，§2） |
| `count` | **0** | 走 `flow_control`（本版未用） |
| 顶层 `vnc` 子映射 | **0** | 已住 `layers[1].vnc`（21/21）；**且顶层形式今日判死**（`rawWrapChains` 表） |
| `strategy_fc` / `flow_control` | **0** | 本协议无多流用例；目标形按需加 |

**结论**：**本协议存量 21/21 顶层零残留**——§1 门的动作 = ①**无旧键可删**；②收官自查行「非负例顶层键 = 0」**今日即成立**（机读实测 21/21 顶层仅 `layers`）；③A′ 新增例全部沿用纯 layers 形（§13）。
> **注（2026-09-29 机读）**：全仓 `cases/*.json` 中已有多个协议是纯 `{layers}` 形（bacnet/dcerpc/dtls/edp/ftp/hl7/igmp/jt808/jt809/jtt905/kerberos/kingbase/ldap/megaco/mmse/ntlm/ocsp/opcua/pppoe/pptp/rtmp/rtsp/sctp/sstp/**vnc**/xmpp/xmrmining 等），本协议只是其中之一，**并非"唯一"**。本协议的**特有事实**仅是"21/21 例今日即零残留"。

目标形状样例见 §2（顶层仅 `layers`）。

### 12-P2 判死负例形状（链级红例必含清单①③④）

- ① presence 形状 `{"layers":[…],"vnc":{}}` 今日**会被拒**（`rawWrapChains` 表含 vnc，报 `no longer accepts a top-level vnc sub-config`）——**与 opcua 相反**：本协议该负例**可建且会真红**；但存量未建，建例属 JSON 阶段动作 → G-VNC-18。② 白名单外游离键判死（`unknown field`）今日**无通用门** → 框架面缺口（与 moxa/opcua 同款，**不单独立项**）。③ 4 负例每条带锚词（已齐，§7）。④ 收官自查「非负例顶层键 = 0」**今日已成立**（§12.1）。

### 12.3 §3 强制展开：五件套

- **会话表**：`s1` 单连接基线（21/21 例，各自四元组，TCP 握手 → 版本 ×2 → 安全协商 → 认证 → ClientInit/ServerInit → 消息面 → FBU 循环 → 拆链）。**无 `s2`**——`VNCConfig` 无 `Sessions` 字段，协议层是**单连接单会话**（§4 业务层结论）；多连接由策略级 `flow_control` 承载（本版未用）。
- **事务序列**：`t1` TCP 建连（SYN/SYN-ACK/ACK，本层自建）/ `t2` 版本交换（H1/H2）/ `t3` 安全类型协商（H3/H4，+Tight 的 H5/H6/H7）/ `t4` 认证（H8/H9/H10，失败则提前进 `t6`）/ `t5` 初始化（ClientInit/ServerInit，+Tight InteractionCaps）/ `t6` 消息面（C1–C6 ↔ S1–S4，按 `rounds`×`fbu_update_interval` 展开）/ `t7` 关闭（FIN 四包）。每事务四件事（前置/触发/成功/失败）见 §5.1 状态表 + §5.2 事件序。
- **关联关系**：**无派生流**（诚实声明：单 TCP 连接承载全部消息，无 `driven_by`；FBU 不派生新连接）。**无关联标识**（RFB 无 transactionId/TID——关联靠**顺序**与**语义位置**，§5 事务定义）。
- **插入位置**：**raw-IP 终结层**（`[ip,vnc]`，链上无 tcp 层；TCP 握手/分段/拆链由生成器 `Plan` 自建，`layer_gen.go:54` 把每包 `Direction` 改写为 `"up"` 以防 raw-IP drive 二次换向）。
- **时间线**：握手阶段**严格交替**（server→client→…）；数据面**客户端驱动**（C5 PointerEvent → S1 FBU，每轮）；extras 在**每个 FBU 之前**按固定顺序发射（§3.7）；`rounds × fbu_update_interval` **线性展开**（T-12 实测）；**无交错**（`concurrent` 为例外路径不启用）。

### 12.12 §12 强制展开：动态字段清单与序号算法

四元组 `ip.src/dst`、`tcp.src_port/dst_port` **五策略全开**（allowlist `internal/core/layer_dyn.go` 头部实测：`ip`/`tcp`/`udp`/`eth` + 10 个业务协议；**无 `vnc` 行**）。保底 `DefaultSrcPort = 12345`（`strategy_convert.go:49`）+ worker 注入 `12345+i`；`dst_port` 动态与 5900 缺省和平共处（`setDefaultDstPort` 只在键**缺失**时补，`strategy_convert_helpers.go:41-46`——显式/动态值非零即不触发补齐）。

**业务字段 26 项全关**（allowlist 无 `vnc` 行，机读实测零命中；对象即 `does not support dynamic`），逐项理由：

| 组 | 字段 | 开/关 | 理由 |
|---|---|---|---|
| 安全 | `security_type` / `auth_result` / `auth_reason` | 关 | 通道级标量，逐流变无意义（且 `security_type` 决定整条握手序列形状，逐流变会破坏帧数可预测性） |
| 会话 | `share_desktop` | 关 | 布尔开关 |
| 屏幕 | `width` / `height` / `server_name` / `pixel_format` | 关 | 初始化参数，逐流变无意义（`pixel_format` 是嵌套对象，无动态形状） |
| 能力 | `interaction_caps` | 关 | 嵌套对象（4 子键 + caps 列表），无动态形状 |
| 输入 | `key_events` / `pointer_x` / `pointer_y` / `pointer_button` | 关 | 列表/标量，逐流变破坏交互语义 |
| 消息面 | `client_set_pixel_format` / `client_set_encodings` / `encodings` / `rounds` / `fbu_update_interval` | 关 | 布尔开关 / 列表（含负值伪编码，无动态形状）/ 结构选择器 |
| FBU | `initial_fbu` / `update_rects` | 关 | 列表（rect 记录 7 键，含 hex 原文子键），无动态形状 |
| 服务端 extras | `bell` / `set_colour_map_entries` / `server_cut_text` / `client_cut_text` | 关 | 布尔开关 / 嵌套对象 / 字符串（逐流变无现网需求） |
| 认证字节 | `challenge_seed` / `response_seed` | 关 | uint64 种子（逐流变 = 破坏可复现性，与设计目标相反） |

逐流变体需求列 A′ 候选（testcase §6.2；今日按 CORE_MEMORY §9.36 口径**不冒充覆盖**）。

序号算法实读：`parseLayerDyn`（`layer_dyn.go:78`）/ `TupleGenerator.Next`（`tuple_generator.go`）/ 保底自增（`strategy_convert.go:49` + worker 注入）/ allowlist 白名单（`layer_dyn.go:19-76`）——**`vnc` 无块**（grep 实测零命中），即层内任何对象值 → `does not support dynamic`。

## 13. P3 对接清单（T-VNC 草稿输入；正文落 testcase 文件）

21 ID（17 正 + 4 负）+ packet_count/锚词 + fixture 常量 + 双通道断言基线 + 存量审计（testcase §2–§5/§8 全量）。

**A′ 候选（按缺口号排序）**：
`vnc_ipv6`（G-VNC-1）/ `vnc_neg_bad_colour_hex`（G-VNC-6）/ `vnc_neg_bpp` + `vnc_neg_depth` + `vnc_neg_rect_bounds`（G-VNC-3）/ `vnc_rect_custom_tile` + `vnc_rect_custom_xcursor`（G-VNC-5）/ `vnc_auth_result_2`（G-VNC-3）/ `vnc_default_port` + `vnc_nondefault_port`（G-VNC-12）/ `vnc_multi_flow`（G-VNC-12）/ `vnc_pixel_format_full`（G-VNC-10）/ `vnc_empty_key_events`（G-VNC-3）/ `vnc_large_raw_segment`（G-VNC-4）/ `vnc_abort_rst`（G-VNC-14）/ `vnc_presence_neg`（G-VNC-18，**会真红**）。

## 14. 缺口立项清单（有缺口写「缺口立项」，不许空着）

| 缺口 | 内容 | 去向 |
|---|---|---|
| **G-VNC-1** | **IPv6 零用例**：21/21 例为 IPv4（`10.0.0.1 → 20.0.0.1`），36 条 frame 断言**全部 offset 54**；`EtherTypeFor(spec.SrcIP)`（`vnc.go:688`）与 `L3Base` 支持 IPv6，单测 `TestIPv6Hosts`（`vnc_test.go:591`）覆盖，但**无 pcap 用例** | A′ 补例 `vnc_ipv6`（断言 offset **74** + `ipv6.src/dst`）；P4 必做 |
| **G-VNC-2** | **1 例负例 pcap 未留档**：`/tmp/mcp-pcaps/vnc/` 有 20 例（17 正 + 3 负），缺 `vnc_t15_neg_auth_result.neg.pcap`（用例在 JSON 中，第 15 位）。其余 3 负例 pcap 均 **0 帧**实测 | P4 重跑套件补齐留档；在此之前**不得**声称该例已复跑 |
| **G-VNC-3** | **18 条拒绝分支零覆盖**（§7 表）：source/destination IP 解析、`vnc config is required`、height、rounds、pointer x/y/button、fbu_update_interval、pixel format bpp/depth、key、encoding、rect 范围、xcursor blob、hextile data、colour hex；另 `auth_result=2`、`rounds=0`、`fbu_update_interval=0`、`key_events: []`、`auth_reason` 在成功时被丢弃 | A′ 补例（分组覆盖，同分支可合并）；P4 |
| **G-VNC-4** | **分段路径零证据**：`segmentByMSS`（`:838`）已落码，但存量最大实测 `tcp.len=1024`（< MSS 1460），**无一例触发分段**。触发条件：raw 矩形 `w×h×4 + 12 > 1460`（即 `w×h > 362`） | A′ 补例 `vnc_large_raw_segment`（如 20×19 raw，断言**两帧** PSH-ACK + seq 推进）；P4 |
| **G-VNC-5** | **rect 子键 `hextile_tile_data` / `xcursor_blob` 零用例**（21 例 rect 只用 x/y/width/height/encoding 五键，机读实测）；且 `validateRect` 对 `XCursorBlob` 只校验 `len ≥ 6`（`:210`），对 `HextileTileData` 路径**不校验瓦片数与尺寸一致性**——配置写错会静默产出长度不符的 FBU | A′ 补例 `vnc_rect_custom_tile` + `vnc_rect_custom_xcursor`；P4 同时裁定是否加长度精确校验 |
| **G-VNC-6** | **`SetColourMapEntries` 静默补零**：`buildSetColourMapEntries:456-462` 对非 6 字节的合法 hex（如 `"ffff00"` 3B）**静默替换为 6 个 0 字节**；`Validate:190-196` 只校验能否 hex 解码、**不校验长度** → 配置错静默上线 | A′ 补例 `vnc_neg_bad_colour_hex`（`"ffff00"`）；P4 裁定加长度校验或登记为已知宽容 |
| **G-VNC-7** | **像素宽度硬编码 4B/像素**：`rawPixels`（`:508`）/`hextileData`（`:520`）不读 `PixelFormat.BitsPerPixel`——`bits_per_pixel=16` 时 raw 数据长度应为 `w×h×2`，实现仍写 `w×h×4`（T-18 设了 bpp=16 但用缺省 hextile rect，**不触发**） | P4 裁定：实现按 bpp 自适应，或**明确不解决**并在设计/用例中收窄口径（当前 §1 边界 5 已声明） |
| **G-VNC-8** | **`types.go` 注释错**：`VNCRectConfig.XCursorBlob` 注释写 "fixed **80-byte** blob"（`types.go:9243`），实测 `defaultXCursorBlob` 为 **82 字节**（`vnc.go:85-88`，且同文件 `:80-84` 注释自述 82） | P4 改注释（**文档车道不碰 `.go`**，故此处仅登记） |
| **G-VNC-9** | **第三源不完整**：参考现网 pcap 只覆盖 TightVNC 一家实现；RealVNC/TigerVNC/libvncserver 的线字节未取；TightVNC 扩展的**规范出处**（Interaction Caps 记录布局、XCursor 数据段填充）**无正式文档引用**（本版按参考 pcap + 代码反推，§10.5 不一致点） | 待确认：抓其他实现包对照，或查 TightVNC 官方协议文档；确认前按实现钉、**不声称合规** |
| **G-VNC-10** | **`pixel_format` 五字段 `0 → 缺省` 不可表达**：`pixelFormatBytes:269-286` 对 `red_max`/`green_max`/`blue_max`/`red_shift`/`green_shift` 用 `!= 0` 兜底 → **无法显式写 0**（静默变 255/16/8）；且 8 个子键中 6 个（除 bpp/depth）**零用例** | P4 裁定：改 `getIntPresence` 语义（`*int` 指针区分"未给"与"给 0"）或登记为已知限制；A′ 补例 `vnc_pixel_format_full` |
| **G-VNC-11** | **悬空引用**：`vnc.go` 5 处注释引 `design_vnc.md`（`:118`/`:222`/`:307`/`:552`/`:725`），该文件**从未存在**（全仓 grep 仅命中 `vnc.go` 自身） | **本版即落点**：`112-vnc-design.md` §3/§4/§6 承其语义；P4 可把注释改为 `112-vnc-design.md §X`（**文档车道不碰 `.go`**） |
| **G-VNC-12** | **端口与多流零用例**：21/21 例未显式写 `dst_port`（依赖双缺省 5900）；非缺省端口（5901–5909）**零用例**；`flow_control` 多流**零用例**；`VNCConfig` **无 `Sessions` 字段**（协议层多会话显式不适用，§4） | A′ 补例 `vnc_default_port` + `vnc_nondefault_port` + `vnc_multi_flow`；P4 |
| **G-VNC-13** | **`encodings` 范围口径不齐**：registry **不带范围**（含负值伪编码）；`Validate:176` 限 `-256 ≤ e ≤ 0x7FFFFFFF`——**下界 -256 与 i32 最小 `-2147483648` 不对齐**（合法伪编码若 < -256 会被拒；TightVNC 现有伪编码最小 -250，暂无实际冲突）；`server_name` 的 nameLen u32 **无上界守卫** | P4 裁定范围口径；低优先 |
| **G-VNC-14** | **RST 非正常结束补例**（CORE_MEMORY §3.15②后半） | A′ 补例 `vnc_abort_rst`（`tcp.rst` 框架能力，本层零断言）；P4 |
| **G-VNC-15** | **协议版本降级未实现**：`versionString` 恒 `RFB 003.008\n`（`:54`，**不可配**）；RFC 6143 §7.1.1 允许客户端回 `003.003`/`003.007` 触发降级协商——本实现不支持 | **明确不解决**（现网 003.008 已是绝对主流）+ A′ 候选（若需覆盖老服务器场景） |
| **G-VNC-16** | **`hextileData` 预分配容量偏低**：`:521` 预分配 `(w*h*4)/16` 字节，但实际输出（每瓦片 1B ctrl + 全量像素）约为 `w*h*4` → **预分配低约 16 倍**，`append` 多次扩容。非正确性缺陷，影响吞吐 | P4 基准测量后裁定（`hextileData` 瓦片化后总量 ≈ `(瓦片数) + w*h*4`） |
| **G-VNC-17** | **同值双名**：`secTypeVNCAuthCode = 2` 与 `secTypeVNC = 2`（`vnc.go:32-33`）——前者是 AuthCaps 记录的 code，后者是安全类型枚举，**同值不同语义**，可读性隐患 | P4 合并或改名（非缺陷，低优先） |
| **G-VNC-18** | **presence 负例未建**：顶层 `vnc` 子映射今日**已判死**（`rawWrapChains` 表，报 `no longer accepts a top-level vnc sub-config`）——与 opcua 相反，本协议该负例**会真红**；但存量 21 例无此例 | A′ 补例 `vnc_presence_neg`（`{"layers":[…],"vnc":{}}`）；P4 |
| **G-VNC-20** | **可用字段零收编 + 1 条 notes 文案与事实相反**：21 例只用 **15 个 field 名**，而 tshark 3.6.14 有 **249 个 `vnc.*` 字段**——其中 `vnc.key_down`/`vnc.key`/`vnc.pointer_x_pos`/`vnc.pointer_y_pos`/`vnc.button_*_pos`/`vnc.client_set_encodings_num`/`vnc.client_set_encodings_encoding_type`/`vnc.fb_update_encoding_type`/`vnc.fb_update_width`/`vnc.fb_update_height`/`vnc.fb_update_x_pos`/`vnc.fb_update_y_pos`/`vnc.colormap_first_color`/`vnc.client_cut_text`/`vnc.server_cut_text`/`vnc.encoding_name`/`vnc.encoding_vendor`/`vnc.hextile_subencoding` 等**已实测可用却零使用**（§9 表）。**另：存量 `vnc_t8_key_down_explicit` 的 `notes` 写"tshark 不出 key_down 字段"，本轮实测该字段存在且 T-8 帧 19 输出 `1`——文案与事实相反** | A′ 收编上述字段（优先 `key_down`/`key`/`pointer_x_pos`/`pointer_y_pos`/`client_set_encodings_encoding_type`/`fb_update_encoding_type`）；P4 改写 T-8 的 `notes` 文案（**文档车道不碰 JSON**，故此处仅登记） |
| **G-VNC-21** | **`negotiated=false` 不是可执行断言**：`pcaptest` 的 `negotiated` 检查**只在 `true` 时执行**（`internal/pcaptest/verify.go:195` `if c.Expect.Negotiated {…}`）——存量 `vnc_t5_auth_fail` 的 `negotiated=false` **不触发任何检查**，是**文档性标注**（表达"无 ClientInit/ServerInit"），真正的可执行证据是 `packet_count=17` + f13 的 reason 字节 | P4 裁定：或补 `pcaptest` 的 `false` 分支检查（断言"无 ServerInit"），或把该键从 `expect` 移除并改由 `notes` 承载；**不得**继续把它当作已生效断言 |
| **G-VNC-22** | **覆盖反查门口径滞后 + 漏键**：`coverage_gate.py:7172` 的 `check_vnc` 有 **48 行**（21 协议行 + 23 键行 + 4 锚词行），本轮实跑 **48/48 全绿**；但 ① docstring 自述 "T-VNC-1…17，9.52 对账 27/27" 是**历史口径**（追加 4 例后未更新）；② 键行**漏 3 键**（`auth_reason`/`client_set_encodings`/`fbu_update_interval`，registry 26 键 vs 门 23 键）；③ 无「负例 `expect` 严格两键」「fields 名 ⊆ tshark 实测集」等本契约 §9 建议行 | **主线程**在 `coverage_gate.py` 的 vnc 段补：更新 docstring 例数、补 3 键行、登记本契约 §9 的 12 条建议断言（**本车道不碰该文件**） |
| **G-VNC-19** | **结果文档无 pcap 留档**：`trafficgen/docs/protocol-pcap-test/vnc.md`（tracked）末次提交 `34b8154`（2026-09-20）**晚于**判死提交 `0417be5`（2026-09-13）→ **不满足任务书过期判定条件，不登记为过期缺口**；但 `docs/protocol-pcap-test/vnc/` **目录不存在（0 个 pcap）**，21 条链接全死链 | **代码阶段**（P5 重跑套件后重生成该产物 + 补 pcap 留档）；本版**不删不改**（tracked 产物，删除属 P5 动作）；**本车道未依赖该产物的 21/21 数字**（§0 #5/#6） |

## 15. 修订记录

- v1.0.0（2026-09-29）：**批次二 as-built 文档轨首版**。#112 vnc **无旧稿基线**（`docs/protocol-designs/` 下无任何 vnc 文件，§0）；§0 改为"代码内悬空引用 vs 实测事实"五级对照（**1 处注释数值错** `types.go` 80→82、**1 处悬空引用** `design_vnc.md`、**1 处产物判定** 末次提交晚于 0417be5 故**不登记过期**）；§1–§3 逐字段线格式（**全大端**；握手 10 类 + 客户端 6 类 + 服务端 4 类；PIXEL_FORMAT 16B 逐字段；Raw/Hextile/XCursor 三编码数据长度公式）；§5 状态机六态 + 完整事件序 + **包数公式**（17 正例逐例验证 17/17 与实测 pcap 一致）；§6 长度核算逐项可复算（ServerInit 38B / InteractionCaps 184B / SetEncodings 64B / Raw FBU 928B / Hextile FBU 1024B **与实测逐字节吻合**）；§7 负例 4 条锚词 + **21 条拒绝分支逐条列行号**（18 零覆盖）；§9 21 ID 表（17 正 + 4 负，42 field + 36 frame 断言，**15 个 field 名**）+ **可用未收编字段表**（G-VNC-20，含 1 条 notes 文案纠错）；§10 八项矩阵 + 三子表；§11 D-VNC-1 as-built 定稿（1679 行 / 25 Test）；§12 门1 十四行 + 12.1/12.3/12.12 强制展开；§14 缺口 **G-VNC-1…G-VNC-22**（**22 条**，其中 G-VNC-21/G-VNC-22 为用例文档侧发现）。**本车道实跑 20 例 pcap 复核**：17 正例帧数 17/17 一致、36 条 frame + 42 条 field 断言全 OK、3 负例 0 帧、0 malformed。自审 3 轮，末轮干净。

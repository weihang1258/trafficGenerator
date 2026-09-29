# #112 vnc（VNC / RFB）测试用例契约

> 版本：v1.0.0（批次二 as-built 文档轨首版；修订记录见 §10）
> 日期：2026-09-29
> 配套设计：`docs/protocol-designs/112-vnc-design.md` v1.0.0（D-VNC-1）
> 旧基线：**无**（本协议在本仓**从未有过用例文档**；`docs/protocol-designs/` 下无 `*vnc*` 文件，机读实测——设计 §0 #1）
> 机器契约：`trafficgen/test/protocol_pcap/cases/vnc.json`（**21 例 = 17 正 + 4 负**；**21/21 ID 与本版 §2 一致、顺序一致**，机读实测；**21/21 顶层键仅 `{layers}`，零残留**）
> 白话一句：**二十一条检查：十七条看正常收发（三类认证路径、握手字节、屏幕推送、键盘鼠标、剪贴板、色表、编码协商、能力协商、脱敏种子），四条看胡来能不能被拦下；每条只查一件事。**

## 1. 测试原则和形状基线

用例从设计 §3–§9 逐项派生，共 **21 个唯一语义 ID：17 正 + 4 负**（负例 N-1…N-4）。派生规则：设计 §3 每个消息/字段条款、§5 每个事务/自动派生行为、§7 每行错误处理在本文有对应断言；断言不得超出设计声明范围。**一个用例只验证一个协议行为**——但本协议存量存在**复合例**（T-1 全链冒烟、T-9 三消息交织、T-18 三字段定制、T-20 头+记录、T-21 双种子），它们是**集成检查**，其覆盖的原子点由同族原子例分别承接（§6.4 逐项说明）。

**形状基线（2026-09-29 机读实测）**：

| 项 | 实测值 |
|---|---|
| 用例总数 | **21** = 17 正 + 4 负 |
| 顶层键 | **21/21 = `{expect, id, proto, spec_json, summary}`** |
| `spec_json` 顶层键 | **21/21 = `{layers}`（唯一键，零游离键、零顶层 `vnc` 子映射）** |
| 层形 | **`[ip, vnc]` ×21**（无 tcp 层——raw-IP 自驱；**无 IPv6**） |
| 负例 `expect` 键集合 | **4/4 = `{error_contains, expect_error, notes}`**（含 `notes`，非严格两键 → G-VNC-3） |
| 正例 `expect` 键集合 | 4 种：`{frames,has_handshake,negotiated,notes,packet_count,terminates}` ×5；`{fields,frames,has_handshake,negotiated,notes,packet_count,terminates}` ×9；`{fields,has_handshake,negotiated,notes,packet_count,terminates}` ×2；`{fields,frames,has_handshake,has_payload,negotiated,notes,packet_count,terminates}` ×1（T-1） |
| `packet_count` | **17/17 正例全有**；4 负例全无 |
| `fields` 断言 | **42 条**（13 例有，8 例无）；**15 个不同 field 名** |
| `frames` 断言 | **36 条**（18 例有，3 例无）；**全部 `offset: 54`**（IPv4；offset 集合实测 = `{54}`） |
| `notes` | **21/21 例全有**（含 4 负例） |

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`tcp.dstport`、`tcp.flags`、`vnc.*` 字段、offset 54 frames）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；**不设仅单路径可用的断言**——五类断言（`packet_count`/`has_handshake`/`terminates`/`fields`/`frames`）均为路径无关。

**TSHARK 基线（2026-09-29 实测）**：本机 tshark **3.6.14** 有 vnc dissector——`tshark -G fields` 中 `vnc.*` **249 字段**；`tshark -G decodes` 有 `tcp.port 5900/5901/5500/5501 vnc`。**21 例 pcap 全部被解码**（`_ws.col.Protocol = VNC`，实测 `vnc_t1_smoke_ref` 26/33 帧为 VNC、7 帧为纯 TCP 握手/拆链），**零 `_ws.malformed`**（20 例在案 pcap 全扫）。

**进制与字段名纪律（实测）**：`vnc.security_type`、`vnc.client_security_type`、`vnc.auth_result`、`vnc.width`、`vnc.height`、`vnc.client_message_type`、`vnc.server_message_type`、`vnc.fb_update_num_rects`、`vnc.update_req_incremental`、`vnc.share_desktop_flag`、`vnc.server_proto_ver`、`vnc.client_proto_ver`、`vnc.desktop_name` —— **全部十进制/字符串串**（`security_type` 多值时为逗号分隔，如 `"2,16"`）。**字段名以 `tshark -G fields` 实测为准**：`vnc.key_down`/`vnc.key`/`vnc.pointer_x_pos`/`vnc.pointer_y_pos`/`vnc.button_*_pos`/`vnc.client_set_encodings_encoding_type`/`vnc.fb_update_encoding_type` 等**实测存在**（探针验证，设计 §9 表），而 `vnc.bell`/`vnc.pointer_x`/`vnc.pointer_y`/`vnc.button_mask`/`vnc.fb_update_rect_width` **不存在**（0 命中）——**不得臆造字段名**。

**断言基线**：今日 21 例用 `packet_count` + `has_handshake` + `terminates` + `negotiated` + `fields` + `frames` 六类；**42 条 field 断言 + 36 条 frame 断言已逐条对实测 pcap 复核（全 OK）**（§5.1）。

**动态字段禁止硬编码**：生成期值（`clientSeq`/`serverSeq`/`ipID`）在应用层载荷中**不可见**（TCP/IP 头字段，不进 `frames` 断言的 offset 54 区）；`challenge`/`response` 在 seed≠0 时是**确定性**伪随机（xorshift64*，`vnc.go:824`），故 T-21 可硬编码断言（实测复核通过）。

**包数约定（实测公式，设计 §5.3）**：

```
帧数 = 3（TCP 握手）+ H（握手消息数）+ C（客户端消息数）
     + (1 + R×I)（FBU 总数）+ R（PointerEvent）+ E（extras 总数）
     + 1（收尾增量 FBU 请求）+ 4（TCP 拆链）

H = Tight(16) 13 / VNC Auth(2) 9 / None(1) 7
    认证失败时 H 随安全路径取 10 / 7 / 5（Tight / VNC Auth / None），且 C=R=E=0、无收尾增量请求
C = [setPixelFormat?1] + [setEncodings?1] + len(keyEvents) + 1 + [clientCutText?1]
E = (1 + R×I) × ([bell?1] + [colourmap?1] + [serverCutText?1])
```

**17 正例逐例验证 17/17 与实测 pcap 一致**（§5.1）。**负例无 `packet_count`**（实测 3 例在案 pcap 均 **0 帧**，第 4 例 pcap 未留档 → G-VNC-2）。

**保活/重试/RST 口径**：**RFB 无保活/心跳机制**（RFC 6143 无 PING 类消息）——**显式不适用**，不得硬凑保活用例（设计 §10.1 第 6 项）；长会话靠客户端周期发 FBU 请求（`rounds`/`fbu_update_interval` 承载，T-12）；**无重试/重连语义**（认证失败即断，T-5）；RST 为框架 TCP 能力，本协议层零断言（A′ 补例 G-VNC-14）；正例恒 FIN 优雅终止（四包拆链）。

## 2. 原子用例索引（21 ID = 17 正 + 4 负，顺序为权威）

**顺序 = `cases/vnc.json` 数组顺序**（机读实测；非 T 编号顺序）。

| # | ID | 类型 | 覆盖（设计 §） | packet_count | fields | frames |
|---:|---|---|---|---:|---:|---:|
| 1 | `vnc_t1_smoke_ref` | 正 | §3.1–§3.6 全链冒烟（Tight 13 消息 + 消息面 + FBU 循环 + 拆链） | 33 | 23 | 4 |
| 2 | `vnc_t2_handshake_bytes` | 正 | §3.1/§3.2：握手 13 消息逐字节钉 | 33 | 0 | 12 |
| 3 | `vnc_t3_sec_type_vncauth` | 正 | §3.1：VNC Auth 路径（无 caps 三段） | 29 | 3 | 2 |
| 4 | `vnc_t4_sec_type_none` | 正 | §3.1：None 路径（无挑战/应答） | 27 | 2 | 2 |
| 5 | `vnc_t5_auth_fail` | 正 | §3.1 H10 失败分支：reason 透传 + 无 ServerInit + 提前拆链 | 17 | 1 | 2 |
| 6 | `vnc_t6_share_false` | 正 | §3.2：ClientInit shared-flag=0 | 33 | 1 | 1 |
| 7 | `vnc_t7_raw_rect` | 正 | §3.4：Raw 编码确定性像素 | 33 | 0 | 1 |
| 8 | `vnc_t8_key_down_explicit` | 正 | §3.5 C4：KeyEvent 显式单键 down | 28 | 0 | 1 |
| 9 | `vnc_t9_extras_mix` | 正 | §3.7：Bell + ServerCutText + ClientCutText 三消息交织 | 38 | 2 | 3 |
| 10 | `vnc_t10_colourmap` | 正 | §3.6 S2：SetColourMapEntries | 35 | 1 | 1 |
| 11 | `vnc_t11_client_msgs_off` | 正 | §3.5 C1/C2 关闭 | 31 | 1 | 0 |
| 12 | `vnc_t12_rounds_linear` | 正 | §5：rounds=2 × interval=2 线性编排 | 37 | 3 | 0 |
| 13 | `vnc_t13_pointer_default` | 正 | §3.5 C5：PointerEvent 缺省坐标 507/320 | 33 | 1 | 1 |
| 14 | `vnc_t14_neg_sec_type` | **负** | §7 N-1：`security_type=7` | —（0 帧） | 0 | 0 |
| 15 | `vnc_t15_neg_auth_result` | **负** | §7 N-2：`auth_result=3`（V9 区间） | —（0 帧，**pcap 未留档**） | 0 | 0 |
| 16 | `vnc_t16_neg_rect_encoding` | **负** | §7 N-3：rect `encoding="jwt"` | —（0 帧） | 0 | 0 |
| 17 | `vnc_t17_neg_width_zero` | **负** | §7 N-4：`width=0`（显式 0 过 V9） | —（0 帧） | 0 | 0 |
| 18 | `vnc_t18_init_customize` | 正 | §3.2/§3.3：ServerInit 定制（name/w/h/pixel_format） | 33 | 3 | 1 |
| 19 | `vnc_t19_encodings_pointer` | 正 | §3.5 C2/C5：SetEncodings 显式列表 + PointerEvent 显式坐标 | 33 | 1 | 2 |
| 20 | `vnc_t20_caps_customize` | 正 | §3.2：InteractionCaps 定制（头 + 2 记录） | 33 | 0 | 1 |
| 21 | `vnc_t21_seeds` | 正 | §3.1 H8/H9：challenge/response seed 确定性字节 | 33 | 0 | 2 |

**T-编号对照**：`vnc_t<N>_<行为>` 的 `N` 即 T 编号（T-1…T-21），**与 JSON 顺序一致**（唯一例外见注）。

> **注（顺序权威性）**：JSON 中 `vnc_t18_init_customize`…`vnc_t21_seeds` 位于 4 个负例**之后**（追加轮补入，commit `34b8154`）；T-1…T-17 在前。**ID 集合与顺序以 JSON 为权威**（本表已逐位对齐，机读实测）。

## 3. 正例逐项断言契约（最低断言集，实现期可增不可减）

每例均含 `packet_count` + `has_handshake` + `terminates` + `negotiated` + `notes`；帧位由 §1 公式与实测 pcap 双向确认。

### 3.1 `vnc_t1_smoke_ref`（33，23 field + 4 frame）

**配置**：`layers=[{ip:{src:10.0.0.1,dst:20.0.0.1}},{vnc:{initial_fbu:[xcursor(0,1,12,19),hextile(0,0,12,19)],update_rects:[hextile(0,0,12,19)],rounds:1}}]`（**Tight 缺省路径**）。

- `has_handshake=true`、`has_payload=true`、`negotiated=true`、`terminates=true`、`packet_count=33`。
- **fields（23 条，逐条实测复核 OK）**：f1 `tcp.flags=0x002` + `tcp.dstport=5900`；f2 `tcp.flags=0x012`；f3 `tcp.flags=0x010`；f4 `vnc.server_proto_ver=003.008`；f5 `vnc.client_proto_ver=003.008`；f6 `vnc.security_type=2,16`；f7 `vnc.client_security_type=16`；f13 `vnc.auth_result=0`；f14 `vnc.share_desktop_flag=1`；f15 `vnc.desktop_name=QTMS:1 (ykaul)` + `vnc.width=1024` + `vnc.height=768`；f17 `vnc.client_message_type=0`（SetPixelFormat）；f18 `=2`（SetEncodings）；f19 `=4`（KeyEvent）；f25 `=3`（FBU 请求）；f26 `vnc.server_message_type=0`（FBU）+ `vnc.fb_update_num_rects=2`；f27 `vnc.client_message_type=5`（PointerEvent）；f28 `vnc.server_message_type=0`；f29 `vnc.client_message_type=3` + `vnc.update_req_incremental=1`。
- **frames（4 条，offset 54）**：f25 `03 00 00 00 00 00 04 00 03 00`（非增量 FBU 请求，w/h=1024/768）；f26 `00 00 00 02 00 00 00 01 00 0c 00 13 ff ff ff 10`（FBU 头 nRects=2 + rect#1 x=0 y=1 w=12 h=19 encoding=`ff ff ff 10`=-240 XCursor）；f28 `00 00 00 01 00 00 00 00 00 0c 00 13 00 00 00 05`（FBU 头 nRects=1 + rect x=0 y=0 w=12 h=19 encoding=5 Hextile）；f29 `03 01 00 00 00 00 04 00 03 00`（增量 FBU 请求，incremental=1）。
- **包数证据**：`3 + 13 + 9 + 2 + 1 + 0 + 1 + 4 = 33` ✓（§1 公式）。
- **`vnc.security_type=2,16` 的含义（须写清）**：该字段是**服务端报出的类型列表**（count=2，类型 2 与 16），**逗号分隔**；`vnc.client_security_type=16` 是客户端**所选单个类型**——两者不同字段、不同语义，不可混用。

### 3.2 `vnc_t2_handshake_bytes`（33，0 field + 12 frame）

**配置**：同 T-1（Tight 缺省）。

- **frames（12 条，offset 54，逐条实测复核 OK）**：f4 `52 46 42 20 30 30 33 2e 30 30 38 0a`（`RFB 003.008\n` 12B，服务端）；f5 同（客户端回显）；f6 `02 02 10`（secTypes count=2 + 2 + 16）；f7 `10`（客户端选 16）；f8 `00 00 00 00`（TunnelCaps none）；f9 `00 00 00 01 00 00 00 02 53 54 44 56 56 4e 43 41 55 54 48 5f`（AuthCaps：count=1 + code=2 + `STDV` + `VNCAUTH_`）；f10 `00 00 00 02`（选 VNC Auth）；f11 `46 70 8d dc 13 a8 b3 13 c5 99 1e 6d ec fa f2 80`（challenge 16B）；f12 `df 13 24 a5 0b 30 90 3a 38 c8 f9 b8 33 26 2c 6e`（response 16B）；f13 `00 00 00 00`（SecurityResult OK）；f14 `01`（ClientInit share=1）；f16 `00 00 00 0b 00 00 00 00 00 00 00 02 53 54 44 56`（InteractionCaps 头 nServer=0/nClient=11/nEnc=0/pad + 首记录 code=2 `STDV`…）。
- **参考 pcap 逐字节证据**：f4/f5/f6/f7/f8/f9/f10/f11/f12/f13 **与参考现网 pcap（`/home/pcap_auto/llcj_pcap/IP-TCP-10.3.1.143-…-2262354.pcap`）帧 4/5/7/8/9/10/12/13/15/16 的 `tcp.payload` 逐字节相同**（本轮实测对照）。
- **InteractionCaps 记录数语义（T-20 的教训）**：tshark 记录数 = `nServer + nClient + nEnc`；缺省头 `0/11/0` 配 11 条记录 ✓；若写 `nServer=1` 而记录只有 2 条则 **tshark 报 malformed**（T-20 的 notes 记载该修正）。

### 3.3 `vnc_t3_sec_type_vncauth`（29，3 field + 2 frame）

**配置**：`security_type=2` + 同 T-1 的 rect 配置。

- `packet_count=29`（`3 + 9 + 9 + 2 + 1 + 0 + 1 + 4 = 29` ✓）。
- fields：f6 `vnc.security_type=2`（**单值**，无逗号）；f7 `vnc.client_security_type=2`；f10 `vnc.auth_result=0`。
- frames：f6 `01 02`（count=1 + type 2）；f7 `02`。
- **路径差异证据**：比 Tight 少 TunnelCaps/AuthCaps/VNC-Auth 选择/InteractionCaps **共 4 条消息**（33−4=29）；challenge/response 在 **f8/f9**（Tight 下在 f11/f12）。

### 3.4 `vnc_t4_sec_type_none`（27，2 field + 2 frame）

**配置**：`security_type=1` + 同 T-1 的 rect 配置。

- `packet_count=27`（`3 + 7 + 9 + 2 + 1 + 0 + 1 + 4 = 27` ✓）。
- fields：f6 `vnc.security_type=1`；f7 `vnc.client_security_type=1`。
- frames：f6 `01 01`（count=1 + type 1）；f7 `01`。
- **路径差异证据**：比 Tight 少 challenge/response/TunnelCaps/AuthCaps/VNC-Auth 选择/InteractionCaps **共 6 条**（33−6=27）；SecurityResult 直接落在 **f8**（`vnc_t4_sec_type_none` 实测 f8 = `Authentication result`）。

### 3.5 `vnc_t5_auth_fail`（17，1 field + 2 frame）

**配置**：`auth_result=1` + `auth_reason="denied"`（**无 rect 配置**——失败即断，消息面不产）。

- `has_handshake=true`、**`negotiated=false`**、`terminates=true`、`packet_count=17`（`3 + 10 + 0 + 0 + 0 + 0 + 0 + 4 = 17` ✓）。
- fields：f13 `vnc.auth_result=1`。
- frames：f8 `00 00 00 00`（TunnelCaps）；f13 `00 00 00 01 00 00 00 06 64 65 6e 69 65 64`（**u32(1) + reasonLen 6 + `denied`**，共 14B）。
- **`negotiated=false` 的语义（须写清）**：`negotiated` 断言的是"**至少一个 SYN+ACK 包**"（`pcaptest/verify.go:195-207`）——T-5 有 SYN+ACK（f2），故该断言**仍为真**？**实测该用例 `negotiated=false`**。**诚实声明**：`negotiated=false` 在本例中是**语义上"未完成协议协商"的人工标注**，而 `pcaptest` 的 `negotiated` 检查**只在 `true` 时执行**（`if c.Expect.Negotiated {…}`，`verify.go:195`）——**`false` 不触发任何检查**。故该键是**文档性标注**（表达"无 ClientInit/ServerInit"），**非可执行断言**；真正的可执行证据是 `packet_count=17`（比 Tight 正例少 16 帧）与 f13 的 reason 字节。**列 G-VNC-21**。
- **无 ClientInit/ServerInit 证据**：帧 14–17 为 FIN-ACK/ACK/FIN-ACK/ACK 四包（实测 `tcp.len=0`，无 `Share desktop flag` / `Server framebuffer parameters` 行）。

### 3.6 `vnc_t6_share_false`（33，1 field + 1 frame）

**配置**：`share_desktop=false` + 同 T-1 的 rect 配置。

- `packet_count=33`（内容变、结构不变）。
- fields：f14 `vnc.share_desktop_flag=0`。
- frames：f14 `00`。
- **对照**：缺省 `share_desktop` 的 `01` 由 T-1 承接（T-1 帧 14 的 `vnc.share_desktop_flag` 实测为 `1`）。

### 3.7 `vnc_t7_raw_rect`（33，0 field + 1 frame）

**配置**：同 T-1 但 `update_rects=[raw(0,0,12,19)]`。

- `packet_count=33`（编码类型变、帧数不变）。
- frames：f28 `00 00 00 01 00 00 00 00 00 0c 00 13 00 00 00 00 01 02 03 04 0e 0f 10 11`——FBU 头 nRects=1 + rect x=0 y=0 w=12 h=19 + **encoding=0（`00 00 00 00`）** + 前 6 个像素字节。
- **像素确定性证据**：像素 n（行主序）= `[(n*13+1)&0xFF, (n*13+2)&0xFF, (n*13+3)&0xFF, (n*13+4)&0xFF]`（`vnc.go:508-514`）——n=0 → `01 02 03 04`；n=1 → `0e 0f 10 11` ✓（`0e`=14=`1*13+1`）。
- **长度证据**：12×19 raw 数据 = **912B** + 12B rect 头 + 4B FBU 头 = **928B** ≤ MSS 1460 → **单帧**（实测 f28 `tcp.len=928` ✓）。

### 3.8 `vnc_t8_key_down_explicit`（28，0 field + 1 frame）

**配置**：`key_events=[{down:true, key:65513}]`（**替代缺省 6 键**）+ 同 T-1 的 rect 配置。

- `packet_count=28`（`3 + 13 + 4 + 2 + 1 + 0 + 1 + 4 = 28` ✓；显式 1 键替代缺省 6 键 → 33−5=28）。
- frames：f19 `04 01 00 00 00 00 ff e9`（type 04 + **down=01** + pad 2B + key u32 `00 00 ff e9` = 65513 = Page_Up）。
- **可执行字段（本轮实测，A′ 收编候选 G-VNC-20）**：`vnc.key_down` 在 f19 = **`1`**、`vnc.key` = **`0x0000ffe9`**——**存量 `notes` 称"tshark 不出 key_down 字段"与实测相反**（该字段存在且输出 1）。
- **对照**：缺省 6 键全为 `down=false`（T-1 帧 19–24，`vnc.key_down` 全 `0`、`vnc.key` = `0x0000ffe9/ffe3/ffe1/ffea/ffe4/ffe2`）。

### 3.9 `vnc_t9_extras_mix`（38，2 field + 3 frame）

**配置**：`bell=true` + `server_cut_text="brd"` + `client_cut_text="cp"` + 同 T-1 的 rect 配置。

- `packet_count=38`（`3 + 13 + 10 + 2 + 1 + 4 + 1 + 4 = 38` ✓；extras 总数 E = (1+1×1)×2 = **4**：Bell×2 + ServerCutText×2）。
- fields：f26 `vnc.client_message_type=6`（ClientCutText）；f27 `vnc.server_message_type=2`（Bell）。
- frames：f26 `06 00 00 00 00 00 00 02 63 70`（type 06 + pad 3B + len 2 + `cp`）；f27 `02`（**Bell 1B**）；f28 `03 00 00 00 00 00 00 03 62 72 64`（type 03 + pad 3B + len 3 + `brd`）。
- **extras 插入位置证据**：Bell f27 + ServerCutText f28 **在 initial FBU 之前**（initial FBU 实测在 f29）；round 内再一轮 → 33+5=38。
- **可执行字段（A′ 候选 G-VNC-20）**：`vnc.client_cut_text` = `cp`（f26）、`vnc.server_cut_text` = `brd`（f28）。
- **tshark 重组伪影（须写清）**：f28 之后的 FBU 段被 tshark 标为 `Server cut text [TCP segment of a reassembled PDU]`（因为 ServerCutText 的 length 字段让 dissector 期待更多数据）——**这是 dissector 显示层伪影，非 malformed**（实测 `_ws.malformed` = 0），帧字节与 `packet_count` 不受影响。

### 3.10 `vnc_t10_colourmap`（35，1 field + 1 frame）

**配置**：`set_colour_map_entries={first:0, colors:["ffff00000000","0000ffff0000"]}` + 同 T-1 的 rect 配置。

- `packet_count=35`（`3 + 13 + 9 + 2 + 1 + 2 + 1 + 4 = 35` ✓；E = (1+1)×1 = 2：colourmap 在每个 FBU 前发射）。
- fields：f26 `vnc.server_message_type=1`。
- frames：f26 `01 00 00 00 00 02 ff ff 00 00 00 00 00 00 ff ff 00 00`（type 01 + pad 1B + first u16=0 + num u16=2 + 6B×2：`ff ff 00 00 00 00` 红+绿+蓝、`00 00 ff ff 00 00`）。
- **可执行字段（A′ 候选 G-VNC-20）**：`vnc.colormap_first_color` = `0`（f26 实测）。
- **对照**：`colourmap` 发射次数 = FBU 总数 = `1 + 1×1` = 2 → 33+2=35。

### 3.11 `vnc_t11_client_msgs_off`（31，1 field + 0 frame）

**配置**：`client_set_pixel_format=false` + `client_set_encodings=false` + 同 T-1 的 rect 配置。

- `packet_count=31`（`3 + 13 + 7 + 2 + 1 + 0 + 1 + 4 = 31` ✓；C = 0+0+6+1+0 = 7）。
- fields：f17 `vnc.client_message_type=4`（**InteractionCaps 后首个客户端消息 = KeyEvent**，SetPixelFormat/SetEncodings 缺席）。
- **无 frames**：本例靠 `packet_count` + 单个 field 断言，帧内容由 T-1/T-8 承接。

### 3.12 `vnc_t12_rounds_linear`（37，3 field + 0 frame）

**配置**：`rounds=2` + `fbu_update_interval=2` + 同 T-1 的 rect 配置。

- `packet_count=37`（`3 + 13 + 9 + (1+2×2) + 2 + 0 + 1 + 4 = 37` ✓；数据面 = initial FBU + (Pointer + FBU×2)×2 + 增量 FBU-req = **8 消息** → 33+4=37）。
- fields：f27 `vnc.client_message_type=5`（第 1 轮 PointerEvent）；f30 `=5`（第 2 轮 PointerEvent）；f33 `vnc.update_req_incremental=1`（收尾增量请求）。
- **线性编排证据**：两轮 PointerEvent 在 f27/f30（**间隔 3 帧 = 1 Pointer + 2 FBU**），非交错、非并发。

### 3.13 `vnc_t13_pointer_default`（33，1 field + 1 frame）

**配置**：同 T-1（**pointer 三键全缺省**）。

- `packet_count=33`。
- fields：f27 `vnc.client_message_type=5`。
- frames：f27 `05 00 01 fb 01 40`（type 05 + button 00 + x u16 `01 fb`=**507** + y u16 `01 40`=**320**——参考 pcap 缺省坐标）。
- **可执行字段（A′ 候选 G-VNC-20）**：`vnc.pointer_x_pos` = `507`、`vnc.pointer_y_pos` = `320`、`vnc.button_1_pos`…`button_8_pos` 全 `0`（f27 实测）。

### 3.14 `vnc_t18_init_customize`（33，3 field + 1 frame）

**配置**：`server_name="SRV-X"` + `width=320` + `height=240` + `pixel_format={bits_per_pixel:16, depth:16}` + 同 T-1 的 rect 配置。

- `packet_count=33`（**ServerInit 内容变、结构不变**）。
- fields：f15 `vnc.width=320`、`vnc.height=240`、`vnc.desktop_name=SRV-X`。
- frames：f15 `01 40 00 f0 10 10 00 01 00 ff 00 ff 00 ff 10 08 00 00 00 00 00 00 00 05 53 52 56 2d 58`——`0140`=320 + `00f0`=240 + **pixel-format 16B**（bpp `10`=16 / depth `10`=16 / big-endian `00` / true-colour `01` / red-max `00ff` / green-max `00ff` / blue-max `00ff` / red-shift `10`=16 / green-shift `08`=8 / blue-shift `00` / pad `00 00 00`）+ nameLen `00000005` + `SRV-X`。
- **`pixel_format` 兜底证据（设计 §3.3）**：只写 `bits_per_pixel`/`depth` 两键，其余 8 键走缺省——实测字节与缺省形（T-1 f15）**除 bpp/depth 外完全相同**（T-1 f15 = `0400030020 18 000100ff00ff00ff1008000000000000000e…`）。
- **长度证据**：ServerInit = `24 + nameLen(5)` = **29B**（实测 T-18 f15 `tcp.len=29` ✓）；对照缺省形 T-1 f15 = **38B** = `24 + 14`（`QTMS:1 (ykaul)`）。
- **bpp=16 的覆盖边界（G-VNC-7，须写清不得含糊）**：本例设了 `bits_per_pixel=16`，但**只用缺省 hextile rect**——`rawPixels`/`hextileData` 的像素宽度**硬编码 4B**（`vnc.go:508`/`:520`），不读 bpp。故本例**只证明 PIXEL_FORMAT 字段被正确写出**，**不证明**像素数据随 bpp 变宽；`bpp=16` 下的像素宽度正确性**今日零证据**（G-VNC-7，设计 §1 边界 5 已声明不实现自适应）。

### 3.15 `vnc_t19_encodings_pointer`（33，1 field + 2 frame）

**配置**：`encodings=[0,5,-240]` + `pointer_button=1` + `pointer_x=100` + `pointer_y=200` + 同 T-1 的 rect 配置。

- `packet_count=33`。
- fields：f27 `vnc.client_message_type=5`。
- frames：f18 `02 00 00 03 00 00 00 00 00 00 00 05 ff ff ff 10`（type 02 + pad 1B + nEnc u16=**3** + `00 00 00 00`=raw 0 / `00 00 00 05`=hextile 5 / `ff ff ff 10`=**-240** XCursor）；f27 `05 01 00 64 00 c8`（type 05 + button **01** + x `0064`=100 + y `00c8`=200）。
- **可执行字段（A′ 候选 G-VNC-20）**：`vnc.client_set_encodings_num` = `3`、`vnc.client_set_encodings_encoding_type` = `0,5,-240`（**逐项对上显式列表**）、`vnc.pointer_x_pos` = `100`、`vnc.pointer_y_pos` = `200`、`vnc.button_1_pos` = `1`。
- **对照**：缺省 15 项（64B）由 T-1 承接；缺省坐标 507/320 由 T-13 承接。

### 3.16 `vnc_t20_caps_customize`（33，0 field + 1 frame）

**配置**：`interaction_caps={server_msg_types:0, client_msg_types:2, encoding_types:0, caps:[{code:5,vendor:"STDV",name:"HEXTILE_"},{code:1,vendor:"STDV",name:"COPYRECT"}]}` + 同 T-1 的 rect 配置。

- `packet_count=33`。
- frames：f16 `00 00 00 02 00 00 00 00 00 00 00 05 53 54 44 56 48 45 58 54 49 4c 45 5f 00 00 00 01 53 54 44 56 43 4f 50 59 52 45 43 54`——头 `nServer=0/nClient=2/nEnc=0/pad` + 记录 1（code 5 + `STDV` + `HEXTILE_`）+ 记录 2（code 1 + `STDV` + `COPYRECT`）= **40B**。
- **`nServer=0` 的必要性（T-20 的 notes 教训）**：tshark 记录数 = `nServer + nClient + nEnc`；原稿写 `nServer=1` 但只有 2 条记录 → **tshark 报 malformed**，修正为 `0/2/0` 后 clean。**这是"字段值必须与记录数自洽"的直接证据**。
- **长度证据**：`8 + 16×2` = **40B**（实测 f16 `tcp.len=40` ✓）；缺省 11 记录 = **184B**（T-1 f16 `tcp.len=184` ✓）。
- **可执行字段（A′ 候选 G-VNC-20）**：`vnc.encoding_name` / `vnc.encoding_vendor`（f16 实测）。

### 3.17 `vnc_t21_seeds`（33，0 field + 2 frame）

**配置**：`challenge_seed=1` + `response_seed=1` + 同 T-1 的 rect 配置。

- `packet_count=33`。
- frames：f11 `47 ab b9 4d 0e c8 d0 ac 56 bf 7f 2d 27 bc df a1`（challenge，seed=1）；f12 **同字节**（response，同种子）。
- **确定性证据（本轮独立复算）**：`seededBytes(1, 16)` 的 xorshift64* 展开 = `47 ab b9 4d 0e c8 d0 ac 56 bf 7f 2d 27 bc df a1`——**与 JSON 断言逐字节相同**（本车道用 Python 独立复算 `vnc.go:824-834` 的算法，结果一致）。
- **两字节相同的成因（须写清）**：`challenge` 与 `response` **各自独立**调 `seededBytes(seed, 16)`，同种子 → 同输出。**这是实现事实，不是断言缺陷**；缺省（seed=0）时两者不同（参考 pcap 的 challenge ≠ response，T-2 f11/f12）。
- **对照**：缺省参考字节由 T-2 承接。

**正例总则**：多轮编排、extras 交织、三类安全路径、seed 驱动均为正例形态；只有**配置错误**（枚举/范围/hex）进入负例（§4）。

## 4. 负例契约

负例必须在 **registry V9 范围检查**或 **planner `Validate`** 阶段失败并传播为 task error，不得产生成功 PCAP、`completed/0 packet` 或只剩 TCP 外壳的假成功（**实测 3 例在案负例 pcap 均 0 帧**，文件名 `<id>.neg.pcap`；第 4 例 pcap **未留档** → G-VNC-2）。锚词与设计 §7 表一一对应、同序：

| # | ID | 故障输入（机读实测） | 拒绝层 | JSON `error_contains` | 代码文案（逐字） | 代码行 |
|---:|---|---|---|---|---|---|
| N-1 | `vnc_t14_neg_sec_type` | `security_type: 7` | planner | `invalid vnc security type` | `invalid vnc security type 7 (allowed: 1, 2, 16)` | `vnc.go:136` |
| N-2 | `vnc_t15_neg_auth_result` | `auth_result: 3` | **registry V9** | `out of range [0,2]` | `layers: layer "vnc" field "auth_result" = 3 invalid: out of range [0,2]` | `registry.go:2012` + `complete.go:325` |
| N-3 | `vnc_t16_neg_rect_encoding` | `update_rects[0].encoding: "jwt"` | planner（`validateRect`） | `invalid vnc rect encoding` | `invalid vnc rect encoding "jwt" (allowed: raw, hextile, xcursor)` | `vnc.go:206` |
| N-4 | `vnc_t17_neg_width_zero` | `width: 0`（**显式 0**） | planner | `invalid vnc width` | `invalid vnc width 0 (allowed: 1-65535)` | `vnc.go:142` |

**锚词口径**：`error_contains` 是**子串**判定；4 例均命中。

**拒绝层分布（须写清）**：**3/4 走 planner `Validate`**，**1/4 走 registry V9**（N-2）。**N-2 的成因**：`auth_result` 在 registry 带 `Min:0,Max:2` 范围 → V9 先于 planner 拦截；planner 的 `invalid vnc auth result %d`（`vnc.go:139`）**经层链不可达**（仅引擎直调绕过 V9 时可命中，设计 §7）。

**N-4 的显式 0 语义（本协议唯一的"V9 放行、planner 拦截"例）**：V9 对 `u == 0` **直接放行**（`complete.go:319-322` "显式 0 = 用 schema 默认值"）——故 `width: 0` **过 V9**，落 planner 的 `< 1` 分支。**该例不可删**（否则该分支零覆盖）。

**负例原子性**：每例单一故障注入；单次执行不得混注。4 例均为**单键注入**，**无并存注入**（与 opcua 存量 N-1 的两注入并存不同）。

**expect 键形状注**：存量 4 负例 `expect` = `{error_contains, expect_error, notes}`（**含 `notes`**），与 92-moxa 范式的严格两键不同 → P4 收窄时删 `notes`（G-VNC-3）。

**未入用例的拒绝分支（A′ 立项，不得冒充已覆盖）**：`Validate`+`validateRect` 共 **21 条** `fmt.Errorf` 分支（`vnc.go:119-220` 逐条机读），今日覆盖 **3 条**（N-1/N-3/N-4），**18 条零覆盖** → 完整清单见设计 §7 表（锚词逐字 + 行号）。

**未入用例的静默路径（缺陷候选）**：① `buildSetColourMapEntries` 非 6 字节 hex **静默补零**（G-VNC-6）；② `pixelFormatBytes` 五字段 `0 → 缺省` **静默改写**（G-VNC-10）；③ `auth_reason` 在 `auth_result=0` 时**静默丢弃**（G-VNC-3）；④ `hextileData` 的 `HextileTileData` 路径不校验瓦片数与尺寸一致性（G-VNC-5）。

## 5. 覆盖与对账

### 5.1 三源回指行 + 本轮实测面

三源 = **RFC 6143 §7–§9 + TightVNC 扩展**（设计 §10）+ **D-VNC-1**（设计 §11）+ **参考现网 pcap（`tshark -Y vnc` 1679 帧）+ 20 例实测 pcap + tshark 3.6.14 字段表（249 字段）** → 21 ID（本契约 §2）。

**本轮实测面（2026-09-29，本车道实跑，非引产物）**：

| 项 | 结果 |
|---|---|
| pcap 在案 | **20/21**（17 正全在 + 3 负；缺 `vnc_t15_neg_auth_result.neg.pcap`） |
| `packet_count` vs 实测帧数 | **17/17 一致**（33/33/29/27/17/33/33/28/38/35/31/37/33/33/33/33/33） |
| 负例帧数 | **3/3 在案者均 0 帧** |
| `frames` 断言 | **36/36 逐条复核 OK**（全部 offset 54） |
| `fields` 断言 | **42/42 OK**（39 条精确串 + 3 条 `tcp.flags` 位比较：JSON `0x002` vs tshark `0x0002`，`pcaptest/verify.go:114` 按位比较，**等价**） |
| `_ws.malformed` | **0**（20 例全扫） |
| 解码率 | `_ws.col.Protocol` = `VNC`（正例 26/33 帧为 VNC，其余 7 帧为 TCP 握手/拆链） |
| 与参考 pcap 对照 | T-2 的 f4/f5/f6/f7/f8/f9/f10/f11/f12/f13 与参考 pcap 对应帧**逐字节相同** |
| T-21 种子独立复算 | `seededBytes(1,16)` Python 独立复算 = `47 ab b9 4d 0e c8 d0 ac 56 bf 7f 2d 27 bc df a1`，**与 JSON 逐字节相同** |

**21 ID 逐项回指（§9.5 要求）**：#1←设计 §3.1–§3.6；#2←§3.1/§3.2；#3←§3.1；#4←§3.1；#5←§3.1 H10；#6←§3.2；#7←§3.4；#8←§3.5 C4；#9←§3.7；#10←§3.6 S2；#11←§3.5 C1/C2；#12←§5.2/§5.3；#13←§3.5 C5；#14←§7 N-1；#15←§7 N-2；#16←§7 N-3；#17←§7 N-4；#18←§3.2/§3.3；#19←§3.5 C2/C5；#20←§3.2；#21←§3.1 H8/H9。

### 5.2 对账两行 + 清单出处声明

- **清单出处声明**：本清单来源 = **RFC 6143 §7–§9 公开语义 + TightVNC 扩展 + 参考现网 pcap（真实 TightVNC 服务器会话）+ 仓库落码反推 + tshark 3.6.14 字段表与 20 例 pcap 实测**，**非纯规范反推**（TightVNC 扩展的正式文档出处未取到 → G-VNC-9）。
- **对账两行（四表逐行相加，行/格粒度每点 1 计，**不扣跨表重叠**——与 opcua 范本同口径）**：
  **要求逻辑点总数 = 117**（八项 **8** 行 + 子表①矩阵 **57** 格 + 子表②变体 **31** 行 + 子表③商业映射 **21** 行）；**用例覆盖数 = 83**（八项已覆 **5** + 矩阵已覆 **38** + 变体已覆 **24** + 商业已覆 **16**）；**不适用 = 6**（八项 **1** + 商业 **5**）；**开放立项 = 28**（八项 **2** + 矩阵 A′ **19** + 变体立项 **7**）。**83 + 6 + 28 = 117** ✓
  **逐表重数（与设计 §10.1–§10.4 逐表结论一一对应）**：八项 8 = 覆 5 + 立项 2 + 不适用 1；矩阵 57 = 覆 38 + A′ 19；变体 31 = 覆 24 + 立项 7；商业 21 = 覆 16 + 不适用 5。**G-VNC-1…G-VNC-20 与 G-VNC-21/G-VNC-22 不折进 117**（缺口单列）。**反查全绿 ≠ 覆盖全**。
- **门3 抽查候选**：最复杂用例 = **#1 `vnc_t1_smoke_ref`**（33 帧：TCP 3 + 握手 13 + 客户端消息 9 + FBU 2 + Pointer 1 + 收尾 1 + 拆链 4；**23 条 field 断言 + 4 条 frame 断言**，交织维度 = 消息类型(13)×方向(2)×安全路径(3)）；**建议门3 抽 #1 + #2**（`vnc_t2_handshake_bytes` 补 12 条握手字节面）。

### 5.3 T-编号与 ID 对照（设计 §9 全表摘要）

`vnc_t1_smoke_ref` ≡ T-1；`vnc_t2_handshake_bytes` ≡ T-2；`vnc_t3_sec_type_vncauth` ≡ T-3；`vnc_t4_sec_type_none` ≡ T-4；`vnc_t5_auth_fail` ≡ T-5；`vnc_t6_share_false` ≡ T-6；`vnc_t7_raw_rect` ≡ T-7；`vnc_t8_key_down_explicit` ≡ T-8；`vnc_t9_extras_mix` ≡ T-9；`vnc_t10_colourmap` ≡ T-10；`vnc_t11_client_msgs_off` ≡ T-11；`vnc_t12_rounds_linear` ≡ T-12；`vnc_t13_pointer_default` ≡ T-13；`vnc_t14_neg_sec_type` ≡ T-14；`vnc_t15_neg_auth_result` ≡ T-15；`vnc_t16_neg_rect_encoding` ≡ T-16；`vnc_t17_neg_width_zero` ≡ T-17；`vnc_t18_init_customize` ≡ T-18；`vnc_t19_encodings_pointer` ≡ T-19；`vnc_t20_caps_customize` ≡ T-20；`vnc_t21_seeds` ≡ T-21。**无虚例**（21 个 ID 全部有独立 JSON 用例；与 opcua 旧稿的 T4/T8 虚例不同）。

## 6. P3 固定动作（CORE_MEMORY 管线：§3.15 三项 + A′/B′ 两分类 + 3.14 豁免）

### 6.1 §3.15 三项逐项一例或立项

| # | 三项 | 本协议对照 | 用例/立项 |
|---|---|---|---|
| ① | 同连接/同流内的多轮操作 | 单 TCP 连接内多轮 FBU 循环（#12：rounds=2 × interval=2 = 2 轮 ×（1 Pointer + 2 FBU）+ 收尾增量请求）；#1 单轮基线 | 已覆 **#12**（+ #1 基线） |
| ② | 非正常结束 | 正常 FIN 四包拆链（全正例）；**应用层"非正常"= 认证失败提前断**（#5，无 ClientInit/ServerInit）；传输异常 = RST（框架 TCP 能力） | 已覆 **#5**；RST **A′ 立项**（G-VNC-14，本层零断言） |
| ③ | 长保活 | **RFB 无保活/心跳机制**（RFC 6143 无 PING 类消息）——**显式不适用** | **不适用**（协议无心跳，**不得硬凑**）；长会话语义由 #12 多轮承载 |

无空项：① 已覆；② 已覆 + 1 条 A′ 立项；③ **显式不适用 + 理由**（设计 §10.1 第 6 项）。

### 6.2 A′/B′ 两分类表

**A′（P4 接线）**：

| 类 | 内容 | 落点 |
|---|---|---|
| 地址族面 | IPv6 独立用例（offset 74）——**今日零用例** | G-VNC-1 |
| 留档面 | 补 `vnc_t15_neg_auth_result.neg.pcap` | G-VNC-2 |
| 拒绝分支面 | 18 条零覆盖分支（source/dest IP、config required、height、rounds、pointer x/y/button、fbu interval、bpp、depth、key、encoding、rect 范围、xcursor blob、hextile data、colour hex）+ `auth_result=2` + `rounds=0` + `fbu_update_interval=0` + `key_events:[]` | G-VNC-3 |
| 分段面 | 大 raw 矩形触发 `segmentByMSS`（`w×h > 362`） | G-VNC-4 |
| rect 子键面 | `hextile_tile_data` / `xcursor_blob` 定制 | G-VNC-5 |
| 色表面 | 非 6 字节 hex 负例（`"ffff00"`） | G-VNC-6 |
| pixel_format 面 | 8 子键全定制（`vnc_pixel_format_full`）+ bpp/depth 负例 | G-VNC-10 / G-VNC-3 |
| 端口/多流面 | `vnc_default_port` + `vnc_nondefault_port`（5901–5909）+ `vnc_multi_flow`（`flow_control`） | G-VNC-12 |
| field 收编面 | `vnc.key_down`/`vnc.key`/`vnc.pointer_x_pos`/`vnc.pointer_y_pos`/`vnc.button_*_pos`/`vnc.client_set_encodings_num`/`vnc.client_set_encodings_encoding_type`/`vnc.fb_update_encoding_type`/`vnc.fb_update_width`/`vnc.fb_update_height`/`vnc.colormap_first_color`/`vnc.client_cut_text`/`vnc.server_cut_text`/`vnc.encoding_name` —— 今日零使用 | G-VNC-20 |
| 非正常结束 | `tcp.rst` 补例 | ② 的 A′（G-VNC-14） |
| presence 面 | `vnc_presence_neg`（顶层 `vnc` 子映射，**今日会真红**——与 opcua 相反） | G-VNC-18 |
| notes 纠错面 | T-8 的 `notes` 文案（称"tshark 不出 key_down"与实测相反） | G-VNC-20 |
| 负例形状面 | 4 负例删 `notes`（严格两键口径） | G-VNC-3 |

**B′（框架面）**：游离顶层键通用门（`CheckProtoFlat` 无 unknown-key 白名单，与 moxa/opcua 同款，**不单独立项**）/ 业务字段动态（allowlist 无 `vnc` 行，G-VNC-3 附）/ `negotiated=false` 语义（`pcaptest` 只在 `true` 时检查，`false` 是文档性标注 → **G-VNC-21**）。

### 6.3 3.14 豁免边界审计

**有长连接载体（TCP）→ `sessions[]` 不豁免**——但本协议 `VNCConfig` **无 `Sessions` 字段**（机读实测），协议层是**单连接单会话**（设计 §4 业务层结论）；**多连接由策略级 `flow_control {"flows": N}` 承载**（本版 21 例未用 → G-VNC-12）。**形态差异已声明**：本协议**不存在** opcua 式"层内 sessions 结构选择器"，也不存在 ftp/sip 式"控制流派生数据流"（VNC 单连接承载全部消息，无副连接）。**多流并发**由 `flow_control` 承载（未用）；**单包多载荷** = **不适用**（RFB 每消息一个类型，无多 question/多 RR 类形态，如实声明）。

### 6.4 复合例的原子点归属（存量 5 例复合检查）

| 复合例 | 复合内容 | 原子点由谁承接 |
|---|---|---|
| #1 `vnc_t1_smoke_ref` | 全链（握手 13 + 消息面 9 + FBU 2 + 拆链） | 握手字节 → #2；三类安全路径 → #3/#4；ClientInit → #6；KeyEvent → #8；Pointer → #13；SetEncodings → #19；编码 → #7；ServerInit → #18；InteractionCaps → #20 |
| #9 `vnc_t9_extras_mix` | Bell + ServerCutText + ClientCutText **三消息同例** | 三消息**各有独立帧断言**（f27/f28/f26）；**今日无单独例**（三键同例触发）→ 若需原子化，A′ 拆三例（G-VNC-3 附） |
| #18 `vnc_t18_init_customize` | server_name + width + height + pixel_format **四字段同例** | 四字段**各有独立 field 断言**（`vnc.width`/`vnc.height`/`vnc.desktop_name`）+ 单条 frame 全钉；**pixel_format 其余 8 子键零覆盖** → G-VNC-10 |
| #20 `vnc_t20_caps_customize` | InteractionCaps 头 + 2 记录 **同例** | 头 3 计数 + 2 记录在**单条 frame 断言**内逐字节钉；记录数自洽（nServer=0）由 tshark 解码干净间接证明 |
| #21 `vnc_t21_seeds` | challenge + response **两字段同例** | 两帧各自断言（f11/f12）；**同种子同字节是预期行为**（§3.17），故合例合理 |

**判定**：5 例复合检查**均有原子点承接**（除 #9 的三 extras 与 #18 的 pixel_format 子键，已列 A′ 候选），**不构成"用大用例替代原子覆盖"**。

## 7. 实现后执行建议

1. **P4 顺序**：①先补 A′ 拒绝分支例（18 条，分组覆盖）；②补 A′ field 收编（G-VNC-20，优先 `key_down`/`key`/`pointer_x_pos`/`pointer_y_pos`/`client_set_encodings_encoding_type`/`fb_update_encoding_type`）；③补 IPv6（G-VNC-1）与分段（G-VNC-4）例；④补端口/多流例（G-VNC-12）；⑤全量复跑 + 补 `vnc_t15` 的负例 pcap 留档（G-VNC-2）。**本协议无 §1 迁移步骤**（顶层零残留）。
2. **实测顺序**：先 #1（33 帧基线）→ #2（握手 12 条字节）→ #3/#4（29/27 帧路径差）→ #5（17 帧失败分支）→ #7（raw 928B）→ #9/#10（extras 35/38）→ #12（37 帧线性）→ #18/#19/#20/#21（定制面）。
3. 二进制与 HEAD 同代确认（门2③：`find trafficgen -name '*.go' -newer <server-binary>` 无输出）；门2② 全量（`CASE_PROTO=vnc` 全量不是增量）；门2④ 反查绿后进 P6。
4. 任何 TightVNC 扩展条款的具体引用须有规范原文证据（G-VNC-9 纪律）。

## 8. 存量审计（21 例逐条去向）

### 8.1 存量实测面（2026-09-29）

`cases/vnc.json` **21 例**：17 正带 `packet_count`（33/33/29/27/17/33/33/28/38/35/31/37/33/33/33/33/33），**与实测 pcap 帧数 17/17 逐例一致**；4 负 `expect` 键集合 `{error_contains,expect_error,notes}`，**3 例在案 pcap 均 0 帧**（第 4 例未留档）；**21/21 顶层键仅 `{layers}`（零残留）**；**42 条 field + 36 条 frame 断言逐条对实测 pcap 复核（全 OK）**；层内 `vnc` 已带 **26 键**（与 registry Fields 逐键一致，机读实测）。

### 8.2 现状矛盾点（P4 前诚实登记）

1. **1 条 `notes` 文案与事实相反**：`vnc_t8_key_down_explicit` 的 `notes` 写"tshark 不出 key_down 字段"——本轮实测 `vnc.key_down` **存在**且 T-8 帧 19 输出 **`1`**（G-VNC-20）。**本契约 §3.8 已诚实声明事实，但存量 JSON 的 notes 字段本身仍是错的**，P4 必须改写。
2. **`negotiated=false` 是文档性标注，非可执行断言**：`pcaptest` 的 `negotiated` 检查**只在 `true` 时执行**（`verify.go:195`）——T-5 的 `negotiated=false` 不触发任何检查，其语义（"无 ClientInit/ServerInit"）靠 `packet_count=17` + f13 reason 字节间接证明（G-VNC-21）。
3. **`types.go` 注释错（80 → 82）**：`VNCRectConfig.XCursorBlob` 注释写 "fixed 80-byte blob"，实测 `defaultXCursorBlob` **82 字节**（设计 §0 #4，G-VNC-8）。
4. **悬空引用**：`vnc.go` 5 处注释引 `design_vnc.md`，该文件**从未存在**（设计 §0 #1，G-VNC-11）。
5. **结果文档无 pcap 留档（不登记为过期）**：`trafficgen/docs/protocol-pcap-test/vnc.md`（tracked）末次提交 `34b8154`（2026-09-20）**晚于**判死提交 `0417be5`（2026-09-13）→ **不满足过期判定条件，本版不登记为过期缺口**（口径诚实，不套用 pcep/opcua 先例）；但 `docs/protocol-pcap-test/vnc/` **目录不存在（0 个 pcap）**，21 条链接全死链（G-VNC-19）。**本车道未依赖该产物的 21/21 数字**。
6. **未覆盖面**：IPv6、18 条拒绝分支、分段、rect 两子键、pixel_format 六子键、非缺省端口、多流、`auth_result=2`、`rounds=0`、`fbu_update_interval=0`、`key_events:[]`、presence 负例、RST、**15 个可用 field 名零使用** —— 今日零用例（A′ 补，G-VNC-1…G-VNC-20）。
7. **覆盖反查门与用例一致**：`coverage_gate.py` 的 `check_vnc` 有 **48 行**（21 协议行 + 23 键行 + 4 锚词行），**本轮实跑 48/48 全绿**（0 fail）；其 docstring 自述 "T-VNC-1…17，9.52 对账 27/27" 是**历史口径**（追加 4 例后未更新文案），且键行漏 3 键（`auth_reason`/`client_set_encodings`/`fbu_update_interval`）→ G-VNC-22。

### 8.3 逐条去向表（21 行）

| 存量 id | T-编号 | 去向 | 改写动作（P4） |
|---|---|---|---|
| `vnc_t1_smoke_ref` | T-1 | **保留** | 形状已合规；可收编 `vnc.key_down`/`vnc.key`（f19–24）+ `vnc.pointer_x_pos`/`y`（f27）+ `vnc.fb_update_encoding_type`（f26） |
| `vnc_t2_handshake_bytes` | T-2 | **保留** | 形状已合规；可收编 `vnc.encoding_name`/`vnc.encoding_vendor`（f16） |
| `vnc_t3_sec_type_vncauth` | T-3 | **保留** | 形状已合规 |
| `vnc_t4_sec_type_none` | T-4 | **保留** | 形状已合规 |
| `vnc_t5_auth_fail` | T-5 | **保留** | `negotiated=false` 语义收窄说明（G-VNC-21）；补 pcap 留档不适用（该例有 pcap） |
| `vnc_t6_share_false` | T-6 | **保留** | 形状已合规 |
| `vnc_t7_raw_rect` | T-7 | **保留** | 可补 `vnc.fb_update_encoding_type=0` 断言 |
| `vnc_t8_key_down_explicit` | T-8 | **改写** | **`notes` 文案纠错**（"tshark 不出 key_down" → 实测输出 1）+ 收编 `vnc.key_down=1`/`vnc.key=0x0000ffe9`（G-VNC-20） |
| `vnc_t9_extras_mix` | T-9 | **保留** | 可收编 `vnc.client_cut_text=cp`/`vnc.server_cut_text=brd`；三 extras 原子化拆例列 A′ |
| `vnc_t10_colourmap` | T-10 | **保留** | 可补 `vnc.colormap_first_color=0` |
| `vnc_t11_client_msgs_off` | T-11 | **保留** | 形状已合规 |
| `vnc_t12_rounds_linear` | T-12 | **保留** | 形状已合规（3 条 field 已断两轮 Pointer + 增量标志） |
| `vnc_t13_pointer_default` | T-13 | **保留** | 可收编 `vnc.pointer_x_pos=507`/`vnc.pointer_y_pos=320` |
| `vnc_t14_neg_sec_type` | T-14 | **保留** | 删 `notes`（严格两键口径） |
| `vnc_t15_neg_auth_result` | T-15 | **保留** | 删 `notes`；**补 pcap 留档**（G-VNC-2） |
| `vnc_t16_neg_rect_encoding` | T-16 | **保留** | 删 `notes` |
| `vnc_t17_neg_width_zero` | T-17 | **保留** | 删 `notes` |
| `vnc_t18_init_customize` | T-18 | **保留** | pixel_format 8 子键零覆盖 → A′ `vnc_pixel_format_full`（G-VNC-10） |
| `vnc_t19_encodings_pointer` | T-19 | **保留** | 可收编 `vnc.client_set_encodings_num=3`/`vnc.client_set_encodings_encoding_type=0,5,-240`/`vnc.pointer_x_pos=100`/`y=200`/`vnc.button_1_pos=1` |
| `vnc_t20_caps_customize` | T-20 | **保留** | 可收编 `vnc.encoding_name`/`vnc.encoding_vendor` |
| `vnc_t21_seeds` | T-21 | **保留** | 形状已合规（种子确定性已独立复算） |

无"作废不注原因"：**0 作废，0 等价覆盖**（21 例全部保留/改写 + A′ 新增）。**本协议存量 21/21 顶层零残留**（与 opcua/ftp/ldap/jt808 等共多个协议同为纯层链形，**非全仓唯一**；见设计 §12.1 注）。

## 9. 附：覆盖反查门建议断言行（供主线程合后登记；本车道不碰 `coverage_gate.py`）

现有 `check_vnc` **48 行全绿**（本轮实跑）。建议在主线程合入后**追加**下列断言（**每条均可从本契约与 cases JSON 直接机读，不需新造事实**）：

| # | 建议断言 | 依据 |
|---:|---|---|
| 1 | `len(cases['vnc']) == 21` 且 ID 集合 = §2 二十一项，顺序一致 | 本契约 §2 |
| 2 | 21/21 例 `spec_json` 顶层键 ⊆ `{layers}`（**本协议零游离键**） | 本契约 §1；设计 §12.1 |
| 3 | 17 正例 `packet_count` 逐例等于 §1 公式算值（按 spec 推出 H/C/R/I/E） | 设计 §5.3 |
| 4 | 4 负例 `expect` 键 == `{expect_error, error_contains}`（P4 删 `notes` 后） | 本契约 §4 |
| 5 | 负例 `error_contains` ∈ 代码锚词集 `{"invalid vnc security type", "out of range [0,2]", "invalid vnc rect encoding", "invalid vnc width"}` | 设计 §7 |
| 6 | 非负例顶层键计数 == 0（**今日已成立**） | 设计 §12.1 |
| 7 | 每正例至少一条 frames 断言落在 offset 54（IPv4）或 74（IPv6，A′ 补后） | 本契约 §3 |
| 8 | 21 例 `frames` 断言的 offset 集合 ⊆ `{54, 74}` | 本契约 §1 |
| 9 | 42 条 `fields` 断言的 field 名 ⊆ `tshark -G fields` 的 `vnc.*` + `tcp.*` 实测集合（**防臆造字段名**） | 本契约 §1；设计 §9 表 |
| 10 | `check_vnc` 的 26 键行覆盖 registry 全部 26 键（**今日漏 3 键**：`auth_reason`/`client_set_encodings`/`fbu_update_interval`） | G-VNC-22 |
| 11 | `check_vnc` docstring 的例数口径与 `len(cases)` 一致（**今日写 "T-VNC-1…17 / 27/27" 而实际 21 例 / 48 行**） | G-VNC-22 |
| 12 | P4 收编后：T-8 的 `notes` 不含"tshark 不出 key_down"字样（**该文案与实测相反**） | G-VNC-20 |

**另注意**：`trafficgen/docs/protocol-pcap-test/vnc.md`（tracked 产物）写 "Cases: 21 — pass 21"，末次提交 `34b8154`（2026-09-20）**晚于**判死提交 `0417be5`（2026-09-13）→ **不满足任务书过期判定条件，本版不登记为过期缺口**；但 `docs/protocol-pcap-test/vnc/` **0 个 pcap**（目录不存在），21 条链接全死链（G-VNC-19）。**本车道未依赖该产物的 21/21 数字**，而是实跑 `/tmp/mcp-pcaps/vnc/` 的 20 例 pcap（§5.1）。

## 10. 修订记录

- v1.0.0（2026-09-29）：**批次二 as-built 文档轨首版**。**无旧基线**（本协议在本仓从未有过用例文档，设计 §0 #1）；形状基线机读实测（§1，**21/21 顶层零残留**，层形 `[ip,vnc]` ×21）；**42 条 field + 36 条 frame 断言逐条对 20 例实测 pcap 复核（全 OK）**；17 正例 `packet_count` 17/17 与实测一致；包数公式（§1）逐例验证；负例 4 条锚词 + 拒绝层分布（3 planner + 1 V9）；**本轮新发现**：`vnc.key_down` 等 15 个可用字段零收编 + T-8 的 `notes` 文案与实测相反（G-VNC-20）、`negotiated=false` 非可执行断言（G-VNC-21）、`check_vnc` docstring 口径滞后 + 漏 3 键（G-VNC-22）；P3 固定动作（§6，含复合例原子点归属表）；执行建议（§7）；存量审计（§8，21/21 保留或改写，**0 作废**）；覆盖反查门建议断言行（§9，**12 条**，现有 48 行本轮实跑全绿）。缺口范围 **G-VNC-1…G-VNC-22**（配套设计 §14 已同列 **G-VNC-1…G-VNC-22**；其中 **G-VNC-21/G-VNC-22** 是用例文档侧发现，已回写设计 §14）。自审 3 轮，末轮干净。

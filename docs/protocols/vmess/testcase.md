# #130 vmess（VMess）测试用例契约

> 版本：v1.0.0（P-PIPE 批次二文档轨 as-built）
> 日期：2026-09-29
> 配套设计：`docs/protocol-designs/130-vmess-design.md` v1.0.0（D-VMESS-1）
> 旧基线：无（本协议首份用例契约；存量仅 `cases/vmess.json` 单例）
> 机器契约：`trafficgen/test/protocol_pcap/cases/vmess.json`（**1 例，混合过渡形**：`layers` 与顶层 `vmess` 子映射并存；严格层链 schema 仍因终结层 Fields/translate 缺口不可落地——G-VMESS-4；本契约 §2 与其逐条一致，§4 为目标契约待代码补齐后落 JSON）
> 白话一句：**一条检查看正常收发（握手、加密信封、回信、挂断，11 帧长度全对得上），其余四十多条看信封各处尺寸（旧格式、域名、IPv6、分块、复用、心跳）和胡来能不能被拦下；每条只查一件事。**

## 1. 测试原则和形状基线

用例从设计 §3（线格式）、§5（事务）、§7（错误锚词）逐项派生。**一个用例只验证一个协议行为**。依据链：首先是 v2fly 官方 VMess/Mux.Cool 规范（本协议无 RFC，规范语义以 v2fly 开发者文档为准，设计 §3.8 已钉差异），其次是设计文档具体化决策——**凡实现偏离 spec 处（G-VMESS-2/3），断言以实现为权威并显式标注"实现口径"**，不得写 spec 原文当断言。

**存量形状基线（2026-09-30 机读）**：1/1 例顶层键 = `{expect,id,proto,spec_json,summary}`；`spec_json` 顶层 = **`{layers,vmess}`（混合过渡形）**——层链承载地址/端口，但业务配置仍在顶层 `vmess`；严格纯层链待 G-VMESS-4 接线。`expect` 键 = `{fields×8, frames×1, has_handshake, has_payload, negotiated, notes×3, packet_count, terminates}`。

**目标形状基线（P4 落地后）**：全部例 `spec_json` 顶层仅 `{layers}`（+ 可选 `flow_control`）；层链 `[ip,tcp,vmess]`；A′ 目标集为 **32 正例 + 12 负例**；负例 `expect` 严格 `{expect_error, error_contains}` 两键。⚠️ 纯层链今日不可跑（`vmess` 层 Fields 空 + 无 translate 分支，G-VMESS-4）——目标形状是 **P4 接线后**的可提交形状。

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`tcp.flags/tcp.len/tcp.dstport`、frames offset 54/74 hex）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；不设仅单路径可用的断言。

**TSHARK 基线（本车道实测）**：tshark 3.6.14 **无 vmess dissector**（`tshark -G fields` grep -i vmess = 0 命中；`-G decodes` 无绑定）。可用断言通道：① `tcp.flags`（握手/挥手/PSH-ACK）；② `tcp.len`（各帧确定性长度——VMess 帧长由 §3 公式决定，随机槽位不影响长度）；③ `tcp.dstport/tcp.srcport`；④ frames 原始 hex（offset 54/74 起的**确定性字节**——仅版本字节与长度前缀可断言，随机槽位禁止字节断言）。**进制纪律**：`tcp.len`/`tcp.dstport` 用十进制串；`tcp.flags` 用 `0x0NN` 形。

**随机性纪律**：IV（16B）/合成密文 body/Payload/Tag 全部随机填充——**断言只钉**：版本字节（帧首 1B）、帧总长（`tcp.len`）、长度前缀（chunk 2B 大端）。禁止对随机槽位做任何字节/内容断言。

**包数约定（设计 §3.7 公式）**：`单流 = 3(握手) + 1(请求) + C_req + 1(响应) + C_resp + M(MUX) + 4(FIN)`；AEAD 空载荷 C=1（终止空块）、Legacy 空载荷 C=0；缺省（AEAD 无载荷无 MUX）= **11**。心跳 = `3 + 2N + 4`。

**保活/重试/RST 口径**：协议层无保活语义（spec 时间戳 ±30s 是认证窗口非心跳）；实现 `heartbeat` 是生成器场景语义（最小请求对），不是协议心跳——用例断言只钉帧序/帧长，不断言"保活生效"；RST 链上不支持（恒 FIN 4 包，G-VMESS-7）；正例恒 FIN 优雅终止。

## 2. 存量原子用例索引（1 ID，与 cases JSON 逐条一致，顺序为权威）

| # | ID | 类型 | 覆盖（设计 §） | packet_count | 存量形状 |
|---:|---|---|---|---:|---|
| 1 | `vmess-basic-session` | 正 | §3.1/§3.2/§3.3：缺省 AEAD 冒烟（版本字节 + 61/18/54/18 四帧长） | 11 | **混合过渡形，今日可跑**；严格层链待 G-VMESS-4 |

存量 expect 逐条（机读）：`has_handshake=true`、`negotiated=true`、`terminates=true`、`has_payload=true`、`packet_count=11`；fields 8 条（帧 1 `tcp.flags=0x002` + `tcp.dstport=443`、帧 2 `0x012`、帧 3 `0x010`、帧 4 `tcp.len=61`、帧 5 `18`、帧 6 `54`、帧 7 `18`）；frames 1 条（帧 4 offset 54 hex `01`）；notes 3 条。

## 3. 存量正例逐项断言契约（最低断言集，实现期可增不可减）

### 3.1 `vmess-basic-session`（11）

配置（存量）：`vmess={uuid:"12345678-1234-1234-1234-123456789012", port:443}`，tcp 443。缺省推导：encryption=`aead_chacha20_poly1305`、Command=0x01、空地址→AddrType 0x01+4 零字节、PadLen=0。

- `has_handshake=true`、`negotiated=true`（SYN+ACK 存在）、`terminates=true`、`has_payload=true`、`packet_count=11`（= 3+1+1+1+1+4 ✓ 公式）。
- fields：帧 1 SYN `0x002` + dstport 443；帧 2 SYN-ACK `0x012`；帧 3 ACK `0x010`；帧 4 len 61（请求帧）；帧 5 len 18（**客户端**终止空块）；帧 6 len 54（响应帧）；帧 7 len 18（服务端终止空块）。
- frames：帧 4 offset 54 hex `01`（请求版本字节，唯一可断言的确定性载荷字节）。
- **帧长复算（设计 §3 公式）**：请求 = 1+16+28+16 = 61（bodyPlain = 16 UUID+1 Ver+1 Cmd+1 AddrType+4 Addr+2 Port+1 PadLen+2 PayloadLen = 28）✓；响应 = 1+16+21+16 = 54 ✓；终止空块 = 2+16 = 18 ✓。
- **方向事实（存量 notes 已标错，P4 修）**：f5 是**上行**（客户端终止块）、f7 是**下行**（服务端终止块）——设计 §0 #3。
- **随机槽位纪律**：帧 5/6/7 的载荷字节每次生成不同（rand.Read），不做字节断言——与存量 notes 第一条口径一致，但"密钥派生"表述删除（无密钥派生，G-VMESS-1③）。

## 4. 目标契约（P4 待落 JSON 的 A′ 全集：32 正 + 12 负）

> 本节是"规范五层展开"的目标用例集（设计 §4/§9/§10 三子表反推）。**未落 JSON 前不得计入覆盖**（JSON ID 集合纪律）；G-VMESS-4 接线完成前不可执行。依据链缩写：§=设计章节；spec=VMess 规范章节名；mux=Mux.Cool 规范章节名；实现=planner.go/layer_gen.go 行号。

### 4.1 正例（32）

| # | ID | 覆盖（依据） | packet_count | 关键断言 |
|---:|---|---|---:|---|
| 1 | `vmess_req_aead_layerchain` | §3.1（实现口径；G-VMESS-4 接线后复钉 #1） | 11 | 纯层链形全断言同 §3.1 |
| 2 | `vmess_req_legacy_version00` | §3.1（Legacy：Ver 0x00、IV 全随机、body AlterID） | 9 | 帧长 55+4=59（无 PayloadLen 字段）；frames 帧 4 hex `00`；无终止空块（C=0） |
| 3 | `vmess_req_legacy_alterid` | §3.1.1（AlterID=16 入 body 第 17 字节） | 9 | 帧长 59；长度不受 alter_id 值影响（1B 槽） |
| 4 | `vmess_req_addr_domain` | §3.5（AddrType 0x02：1B 长度+域名；spec Instruction Section Addr 定义） | 11+Δ | 帧长 = 57+1+len(domain)；AddrType 字节 `02` 于 bodyPlain 固定位 |
| 5 | `vmess_req_addr_ipv6` | §3.5（AddrType 0x03：16B） | 11 | 帧长 = 57+16 = 73 |
| 6 | `vmess_req_addr_ipv4` | §3.5（AddrType 0x01 显式：4B 裸地址） | 11 | 帧长 61；AddrType 字节 `01` |
| 7 | `vmess_req_port_field` | §3.1.1 字段 6（指令段目标端口 2B 大端；存量 `vmess.port` 与 tcp.dst_port 语义区分） | 11 | 显式 `vmess.port=8443`：帧长不变（2B 槽）；与 `tcp.dstport=443` 并存断言 |
| 8 | `vmess_req_pad_16` | §3.1.1 字段 7-8（PadLen 16 上界） | 11 | 帧长 = 61+16 = 77 |
| 9 | `vmess_req_pad_0` | §3.1.1（PadLen 0 显式） | 11 | 帧长 61（与缺省同长） |
| 10 | `vmess_enc_aes_128_gcm` | §3.6（AEAD 双值同布局） | 11 | 帧长 61 不变（布局选择器非算法） |
| 11 | `vmess_chunk_small` | §3.3（实载荷单块：[len][data][tag]） | 12 | 帧长 = 61；块帧 = 2+n+16；payload=10 → 28 |
| 12 | `vmess_chunk_max` | §3.3（单块上界 0x3FFF；G-VMESS-9 差 1 口径） | 12 | 块帧 = 2+16383+16 = 16401，MSS 分段由 tcp.len 逐段断言 |
| 13 | `vmess_chunk_multi` | §3.3（>0x3FFF 多块 + 终止块） | 12+Δ | 总块字节数 = Σ(2+nᵢ+16)+18 |
| 14 | `vmess_resp_payload` | §3.2（ResponsePayload 实载荷，下行） | 12 | 响应块帧 = 2+n+16；帧长 54+respLen |
| 15 | `vmess_cmd_mux` | §3.4（Command=0x03；实现口径私有扩展 G-VMESS-3） | 11+M | bodyPlain Cmd 字节 `03`；MUX 帧长 = 5+len(payload) |
| 16 | `vmess_mux_new` | §3.4（status 0x01 + 目标地址三元组） | 12 | MUX 帧 = 2+1+2+(1+4+2)=12（IPv4 目标） |
| 17 | `vmess_mux_keep` | §3.4（status 0x02 + Payload） | 12 | 帧长 = 5+len |
| 18 | `vmess_mux_end` | §3.4（status 0x03） | 12 | status 字节 `03` |
| 19 | `vmess_mux_keepalive` | §3.4（status 0x04；mux KeepAlive 状态字） | 12 | status 字节 `04` |
| 20 | `vmess_heartbeat_single` | §3.7（心跳 ×1：3+2+4） | 9 | 帧位：帧 4 请求、帧 5 响应、帧 6-9 FIN |
| 21 | `vmess_heartbeat_count3` | §3.7（心跳 ×3：3+6+4） | 13 | 三对请求/响应交替 up/down |
| 22 | `vmess_ipv6_carrier` | §2（外层 IPv6，offset 74） | 11 | frames 偏移 74 hex `01`；`tcp.len` 断言集不变（协议与地址族解耦） |
| 23 | `vmess_port_nondefault` | §8（显式非标 tcp.dst_port，FieldContract 不强制） | 11 | `tcp.dstport=8443`；帧长不变 |
| 24 | `vmess_default_port` | §2（省略 dst_port → 链缺省 443） | 11 | `tcp.dstport=443` |
| 25 | `vmess_uuid_hex_form` | §3.1.1（UUID hex 32 字符形，parseUUID 双形） | 11 | 同 #1 断言（文本形差异不上线） |
| 26 | `vmess_uuid_uppercase` | §3.1.1（大写 hex 接受） | 11 | 同上 |
| 27 | `vmess_mixed_family_addr` | §3.5（v4 外层 + v6 指令段目标地址，两族解耦） | 11+Δ | 帧长 = 57+16 |
| 28 | `vmess_flow_control_3` | §2（flow_control 多流，混合形过渡或纯层链） | 33 | 3×11；各流四元组独立 |
| 29 | `vmess_legacy_full` | §3.1.1（Legacy 全要素：alter_id+domain+payload） | 9+Δ | bodyPlain = 22+N+Pad 公式复算 |
| 30 | `vmess_pad_domain_combo` | §3.1.1（PadLen+Domain 组合长度公式） | 11+Δ | 57+(1+L)+Pad |
| 31 | `vmess_resp_legacy` | §3.2（Legacy 响应 52+Pad，无 RespPayloadLen） | 9 | 帧长 52 |
| 32 | `vmess_layer_mixed_bridge` | §2 样例二（混合形今日唯一可跑，G-VMESS-4 接线前的回归锚） | 11 | 同 §3.1；P4 接线后**作废**（改纯层链）并登记 |

### 4.2 负例（12，锚词与设计 §7 一一对应）

| # | ID | 故障输入 | error_contains | 代码行 |
|---:|---|---|---|---|
| 33 | `vmess_neg_missing_uuid` | 无 uuid | `uuid required` | planner.go:186 |
| 34 | `vmess_neg_bad_uuid` | `uuid:"xyz"` | `invalid uuid` | :189 |
| 35 | `vmess_neg_bad_encryption` | `encryption:"aes-cfb"` | `unsupported encryption` | :195 |
| 36 | `vmess_neg_alterid_over` | legacy + alter_id=256 | `exceeds 1-byte range` | :203 |
| 37 | `vmess_neg_bad_command` | command=9 | `invalid command` | :214 |
| 38 | `vmess_neg_addrtype_no_addr` | address_type=1 且无 address | `address_type set but address is empty` | :223 |
| 39 | `vmess_neg_bad_addrtype` | address_type=7 | `invalid address_type` | :292 |
| 40 | `vmess_neg_domain_over253` | 254 字符域名 | `domain too long` | :278 |
| 41 | `vmess_neg_port_zero` | vmess.port 缺省/0 | `port required` | :228 |
| 42 | `vmess_neg_pad_over16` | header_pad_len=17 | `header_pad_len` + `exceeds max` | :236$
| 43 | `vmess_neg_udp_on_chain` | command=2 | `not supported on the layer chain` | layer_gen.go:214 |
| 44 | `vmess_neg_empty_layer` | `[tcp,vmess{}]` 纯层链空配置 | `VmessConfig is required` | planner.go:181 |

**负例纯净性**：每例 `expect` 严格 `{expect_error, error_contains}` 两键；执行期零成功包。形状级拒绝（扁平五键 `no longer accepts flat config field`、层内 unknown field）属 schema 面不设协议负例（§1 形状基线；G-VMESS-5 presence 不可建）。

## 5. 覆盖与对账（存量口径）

### 5.1 三源回指行

v2fly 官方 VMess/Mux.Cool 规范（设计 §3.8 差异表已校准）+ D-VMESS-1（设计 §11）+ tshark 3.6.14 实测（0 字段）与探针实测（三形状链路终态）→ 存量 1 ID（§2）。**真实服务器行为未取到** → G-VMESS-10（互通性不声称）。

**存量 ID 回指**：#1 ← 设计 §3.1/§3.2/§3.3 + §9 表行 1。

### 5.2 对账两行

- **要求逻辑点总数 = 69**（八项矩阵 8 行 + 子表① 27 格 + 子表② 24 行 + 子表③ 10 行）；**用例覆盖数（存量口径）= 16**（八项 4 + 子表① 9 + 子表② 4 + 子表③ 1）；**不适用 = 15**（八项 2 + 子表① 12 + 子表③ 1）；**A′ 立项 = 38**（八项 2 + 子表① 6 + 子表② 20 + 子表③ 8）。粒度声明：行/格粒度每点 1 计；G-VMESS-1…11 不折进 69。**反查全绿 ≠ 覆盖全**。逐表重数见设计 §10.1（8=2 覆+4 立项+2 不适用）/§10.2（27=9+6+12）/§10.3（24=4+20）/§10.4（10=1+8+1）。**本行 16+15+38=69 ✓**。
- **门3 抽查候选**：最复杂用例 = A′ #13 `vmess_chunk_multi`（多块+终止块+MSS 分段三重交织）；建议门3 抽存量 #1（唯一可跑回归锚）+ A′ #13。

## 6. P3 固定动作（CORE_MEMORY 管线：§3.15 三项 + A′/B′ 两分类 + 3.14 豁免）

### 6.1 §3.15 三项逐项一例或立项

| # | 三项 | 本协议对照 | 用例/立项 |
|---|---|---|---|
| ① | 同连接/同流内多轮操作 | 单连接请求/响应对 + MUX 多帧（A′ #15-19）；心跳 N 对（A′ #20/21） | A′ 已列 |
| ② | 非正常结束 | 链上恒 FIN 4 包；RST 仅 legacy（G-VMESS-7） | **A′ 立项** `vmess_rst`（legacy 面），归属 G-VMESS-7 P4 裁定后落例或关闭 |
| ③ | 长保活 | heartbeat 场景语义（非协议保活，如实声明） | A′ #20/21 |

无空项：① A′；② A′ 立项；③ A′。

### 6.2 A′/B′ 两分类表

**A′（P4 接线）**：G-VMESS-4 接线（Fields 14 键 + translate 分支 + schemagen 重跑）→ 纯层链 32 正例落地；#1 迁移 + notes 四处修正（G-VMESS-1）；负例族 12 条（§4.2）；G-VMESS-8 三静默路径裁定；G-VMESS-9 chunk 上界口径；G-VMESS-2/3 布局裁定（对齐 or 声明）。

**B′（框架面）**：presence 判死分支（G-VMESS-5，等框架级 unknown-key 白名单，不单独立项）；业务字段动态（G-VMESS-6，allowlist 无 vmess 行）；`validateBaseDstPortHandled` 名单维护（设计 §11.7，随 G-VMESS-4）。

### 6.3 3.14 豁免边界审计

有长连接载体（TCP）→ `sessions[]` 概念**不豁免但本协议不适用**（vmess 无 sessions[] 编排面，单 flow=单连接，设计 §12.3 如实声明）；多流并发由策略级 `flow_control` 承载（A′ #28）；**单包多载荷 = 不适用**（VMess 每帧一个语义单元，无多 question 形态）。

## 7. 实现后执行建议

1. **P4 顺序**：①G-VMESS-4 接线（registry Fields + translate 分支 + schemagen 重跑）；②#1 迁纯层链 + notes 四处修正（G-VMESS-1）；③§4.1 正例按序落地（先 #1 复钉 → 线格式族 #2-10 → chunk/响应 #11-14 → MUX/心跳 #15-21 → 载体/端口 #22-24 → 其余）；④§4.2 负例 12 条；⑤G-VMESS-2/3/8/9 裁定后修订断言。
2. **实测顺序**：先 #1（11 帧基线 + 版本字节），再 #2/#29（Legacy 帧长公式 55/52），再 #4-7（地址族帧长），再 #11-14（chunk 结构），最后 #22（IPv6 offset 74）。
3. 二进制与 HEAD 同代确认；`CASE_PROTO=vmess` 全量；反查绿后进 P6。
4. 任何 v2fly 规范章节引用须以 §3.8 差异表为前提——**实现偏离 spec 处断言实现口径**，不引用 spec 原文当断言。

## 8. 存量审计（1 例逐条去向）

### 8.1 存量实测面（2026-09-30）

`cases/vmess.json` 1 例：正例带 `packet_count=11`（公式 ✓）；`spec_json` 顶层为 `{layers,vmess}` 混合过渡形（严格层链仍待 G-VMESS-4）；expect 8 条 fields + 1 条 frames 与公式/发射序全部自洽；notes 已同步修正为合成 AEAD 布局、f5 上行终止块与链路径缺省 443。

### 8.2 现状矛盾点（G-VMESS-4）

1. **层链未完全收敛**：地址与承载端口已在 `layers`，业务配置仍在顶层 `vmess`；严格层链需要补 registry Fields 与 translate 分支。
2. **presence 不判死**：顶层 `vmess` 子映射无 CheckProtoFlat 分支（G-VMESS-5）。
3. **动态全关**：allowlist 无 vmess 行（G-VMESS-6）。
4. **目标用例尚未落 JSON**：A′ 32 正例 + 12 负例待 G-VMESS-4 接线后按 §4 落地。

### 8.3 逐条去向表（1 行）

| 存量 id | 去向 | 改写动作 |
|---|---|---|
| `vmess-basic-session` | **纳入现状并修正** | 地址/承载端口已在 `layers`；业务键当前仍位于顶层 `vmess` 作为 G-VMESS-4 过渡形；notes 已修正；严格层链接线后迁入 `layers[].vmess.*`。 |

无作废：现状 1 例纳入对账；目标 A′ 新例尚未落 JSON。

## 9. 附：覆盖反查门建议断言行（供主线程合后登记；本车道不碰 `coverage_gate.py`）

| # | 建议断言 | 依据 |
|---:|---|---|
| 1 | `len(cases['vmess']) == 1` 且 ID = `{vmess-basic-session}`（P4 迁移前口径） | 本契约 §2 |
| 2 | 存量例 `spec_json` 顶层 ⊆ `{layers,vmess}`（混合过渡形；G-VMESS-4 接线后改断 `⊆ {layers, flow_control}`） | 本契约 §1 |
| 3 | `packet_count == 11` 且 = 3+1+1+1+1+4（公式机读） | 设计 §3.7 |
| 4 | 8 条 fields 断言帧 1-7 的 flags/len 值序 = `0x002,443,0x012,0x010,61,18,54,18` | 本契约 §3.1 |
| 5 | 帧长公式：请求帧 = `57+N+Pad+payload`、响应帧 = `54+Pad+resp`（N/Pad/payload 由 spec 推出） | 设计 §3.1.1/§3.2 |
| 6 | 版本字节：AEAD 帧 4 offset 54 hex `01`；Legacy 例 hex `00` | 设计 §3.1 |
| 7 | 严格纯层链形状验收：非负例顶层键仅含结构性键（当前过渡例仍有 `vmess`，待 G-VMESS-4 接线后转绿） | 设计 §12.1 |
| 8 | 负例（P4 后）`error_contains` ∈ §4.2 锚词集 12 值 | 设计 §7 |

**另注意**：`docs/protocol-pcap-test/vmess.md` 的 "pass 1" 是过期产物（G-VMESS-11，末次提交早于当前层链迁移）；本车道不以该旧产物声称今日复跑。当前唯一 JSON 正例为混合过渡形；严格纯层链需先完成 G-VMESS-4。

## 10. 修订记录

- v1.0.1（2026-09-30）：按实际 `cases/vmess.json`（`{layers,vmess}` 混合过渡形）校正 §1/§2/§8/§9 的陈旧扁平口径与红项标注；同步 notes 修正说明；D8 违禁表述改为 P4 裁定与迁入计划登记；旧产物仍按 G-VMESS-11 标注未复跑。
- v1.0.0（2026-09-29）：P-PIPE 批次二文档轨 P1-P3。首版用例契约：存量 1 例机读审计；目标契约 §4 全集（32 正 + 12 负，逐 ID 依据链/包数/锚词）；对账 69 点口径；P3 固定动作；执行建议；存量审计；覆盖反查门 8 行。

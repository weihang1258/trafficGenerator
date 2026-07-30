# 单项场景 pcap 覆盖清单（7 个独立场景）

> 生成时间：2026-07-24
> 范围：每个场景独立一个 pcap 文件，便于单独定位问题
> 所有 pcap 已通过 Python 脚本解析，验证数据面/媒体面穿插位置正确

---

## 1. 场景 ↔ pcap 映射总表

| # | 场景 ID | 协议 | 模式 | 数据面方向 | spec 文件 | pcap 文件 | 任务 ID | 包数 | 状态 |
|---|---------|------|------|-----------|----------|----------|---------|------|------|
| 1 | ftp-pasv-retr | FTP | PASV 被动 | down (下载) | `/tmp/mcp-pcaps/single-ftp-pasv-retr.json` | `/tmp/mcp-pcaps/single-ftp-pasv-retr.pcap` | `228349c2-f29f-4536-9050-c43b98898cfb` | 30 | ✅ |
| 2 | ftp-pasv-stor | FTP | PASV 被动 | up (上传) | `/tmp/mcp-pcaps/single-ftp-pasv-stor.json` | `/tmp/mcp-pcaps/single-ftp-pasv-stor.pcap` | `9f4179ce-5e30-483c-b33c-350aa1fbcaea` | 30 | ✅ |
| 3 | ftp-active-retr | FTP | PORT 主动 | down (下载) | `/tmp/mcp-pcaps/single-ftp-active-retr.json` | `/tmp/mcp-pcaps/single-ftp-active-retr.pcap` | `6ee5b309-7adc-4dbd-9b4f-ce246abfb225` | 30 | ✅ |
| 4 | ftp-active-stor | FTP | PORT 主动 | up (上传) | `/tmp/mcp-pcaps/single-ftp-active-stor.json` | `/tmp/mcp-pcaps/single-ftp-active-stor.pcap` | `b656b2c9-f1f8-4902-9f7c-890382d3f209` | 30 | ✅ |
| 5 | sip-rtp-g711 | SIP | G.711 PCMU | up (caller→callee) | `/tmp/mcp-pcaps/single-sip-rtp-g711.json` | `/tmp/mcp-pcaps/single-sip-rtp-g711.pcap` | `ce59c0f2-9977-480a-8c0c-642e843348f4` | 24 | ✅ |
| 6 | sctp-hb-primary | SCTP | 单路径 HB | — | `/tmp/mcp-pcaps/single-sctp-hb-primary.json` | `/tmp/mcp-pcaps/single-sctp-hb-primary.pcap` | `9533a16f-9808-40bd-8905-70613d9e24cb` | 19 | ✅ |
| 7 | sctp-multihoming | SCTP | 多归属 | 备路径 HB | `/tmp/mcp-pcaps/single-sctp-multihoming.json` | `/tmp/mcp-pcaps/single-sctp-multihoming.pcap` | `38c24455-ad34-4891-a45c-4389ef712838` | 18 | ✅ |

---

## 2. 数据面穿插位置验证（核心结论）

| # | 场景 | 数据面/媒体面/HB 位置 | 信令锚点 | 验证结果 |
|---|------|---------------------|---------|---------|
| 1 | FTP PASV RETR | 数据面包 [14..22] | 150 在 [13]，226 在 [23] | ✅ PASS — 数据面夹在 150 和 226 之间 |
| 2 | FTP PASV STOR | 数据面包 [14..22] | 150 在 [13]，226 在 [23] | ✅ PASS — 数据面夹在 150 和 226 之间 |
| 3 | FTP PORT RETR | 数据面包 [14..22] | 150 在 [13]，226 在 [23] | ✅ PASS — 数据面夹在 150 和 226 之间 |
| 4 | FTP PORT STOR | 数据面包 [14..22] | 150 在 [13]，226 在 [23] | ✅ PASS — 数据面夹在 150 和 226 之间 |
| 5 | SIP RTP G.711 | RTP 帧 [8..17] | ACK 在 [7]，BYE 在 [18] | ✅ PASS — RTP 夹在 ACK 和 BYE 之间 |
| 6 | SCTP HB primary | HB+ACK [4..13] | COOKIE-ACK 在 [3] | ✅ PASS — HB 在 COOKIE-ACK 之后 |
| 7 | SCTP multi-homing | HB+ACK [4..13] | COOKIE-ACK 在 [3] | ✅ PASS — HB 在 COOKIE-ACK 之后，且走备路径 10.0.0.2/20.0.0.2 |

### 2.1 FTP 数据方向验证（PSH 源 IP）

数据方向以 **PSH（带 payload）包的源 IP** 为准 - 不是 SYN 源 IP。
因为 FTP 的"谁发起连接"和"谁发送文件字节"是两件事：
- PASV 模式：客户端发起连接（SYN 从客户端），但 RETR 时仍是服务器发文件字节
- PORT 模式：服务器发起连接（SYN 从服务器），但 STOR 时仍是客户端发文件字节

| # | 场景 | 模式/方向 | SYN 源 | PSH 源（文件字节方向）| 验证结果 |
|---|------|----------|--------|---------------------|---------|
| 1 | FTP PASV RETR | PASV / down | 10.0.0.1（客户端开连接）| 20.0.0.1（服务器发文件）| ✅ PASS |
| 2 | FTP PASV STOR | PASV / up   | 10.0.0.1（客户端开连接）| 10.0.0.1（客户端发文件）| ✅ PASS |
| 3 | FTP PORT RETR | PORT / down | 20.0.0.1（服务器开连接）| 20.0.0.1（服务器发文件）| ✅ PASS |
| 4 | FTP PORT STOR | PORT / up   | 20.0.0.1（服务器开连接）| 10.0.0.1（客户端发文件）| ✅ PASS |

---

## 3. 4 个 FTP 场景的详细包序列

### 3.1 FTP PASV RETR (下载) — `single-ftp-pasv-retr.pcap`

```
[ 0] CONTROL [SYN] (no payload)               10.0.0.1:20000 → 20.0.0.1:21
[ 1] CONTROL [SYN+ACK] (no payload)           20.0.0.1:21 → 10.0.0.1:20000
[ 2] CONTROL [ACK] (no payload)
[ 3] CONTROL RSP: 220 Welcome to trafficgen FTP
[ 4] CONTROL CMD: USER anonymous
[ 5] CONTROL RSP: 331 Please specify password
[ 6] CONTROL CMD: PASS guest@
[ 7] CONTROL RSP: 230 Login successful
[ 8] CONTROL CMD: TYPE I
[ 9] CONTROL RSP: 200 Type set to I
[10] CONTROL CMD: PASV
[11] CONTROL RSP: 227 Entering Passive Mode (20,0,0,1,195,80)  ← 服务器告诉客户端端口 50000
[12] CONTROL CMD: RETR /data/file.bin
[13] CONTROL 150: 150 Opening data connection          ← 信令面锚点 1
────────── 数据面 (10.0.0.1:20001 → 20.0.0.1:50000) ──────────
[14] DATA [SYN]                                 plen=0
[15] DATA [SYN+ACK]                             plen=0
[16] DATA [ACK]                                 plen=6
[17] DATA [ACK+PSH] 20.0.0.1:50000→10.0.0.1:20001 plen=124  ← 文件内容 (server→client, 下载)
[18] DATA [ACK]                                 plen=6
[19] DATA [ACK+FIN]                             plen=6
[20] DATA [ACK]                                 plen=6
[21] DATA [ACK+FIN]                             plen=6
[22] DATA [ACK]                                 plen=6
────────── 数据面结束 ──────────
[23] CONTROL 226: 226 Transfer complete                ← 信令面锚点 2
[24] CONTROL CMD: QUIT
[25] CONTROL RSP: 221 Goodbye
[26-29] CONTROL [FIN/ACK 四步拆链]
```

- **数据面 4-tuple**: `10.0.0.1:20001 → 20.0.0.1:50000` (客户端主动连服务器 50000 — PASV)
- **数据面 SYN 方向**: client→server (10.0.0.1 → 20.0.0.1)
- **payload 总字节**: 160 (含 PSH+ACK 的 124 字节文件内容)
- **位置**: 数据面 [14-22] 完全嵌入 [13] 150 响应和 [23] 226 响应之间 ✅

### 3.2 FTP PASV STOR (上传) — `single-ftp-pasv-stor.pcap`

```
[ 0-12] 同上 (握手 + USER/PASS/TYPE/PASV/STOR)
[13] CONTROL 150: 150 Opening data connection
────────── 数据面 (10.0.0.1:20002 → 20.0.0.1:50000) ──────────
[14] DATA [SYN]                                              ← 客户端主动连 (PASV)
[15] DATA [SYN+ACK]
[16] DATA [ACK]
[17] DATA [ACK+PSH] 10.0.0.1:20002→20.0.0.1:50000 plen=120  ← 文件内容 (client→server, 上传)
[18-22] DATA [ACK/FIN 拆链]
────────── 数据面结束 ──────────
[23] CONTROL 226: 226 Transfer complete
[24-29] QUIT + 拆链
```

- **数据面 4-tuple**: `10.0.0.1:20002 → 20.0.0.1:50000`
- **payload 总字节**: 156 (含 120 字节文件内容)
- **位置**: ✅ PASS

### 3.3 FTP PORT RETR (下载) — `single-ftp-active-retr.pcap`

```
[ 0-12] 同上 (握手 + USER/PASS/TYPE/PORT/RETR)
[13] CONTROL 150: 150 Opening data connection
────────── 数据面 (20.0.0.1:20 → 10.0.0.1:20003) ──────────
[14] DATA [SYN] 20.0.0.1:20→10.0.0.1:20003       ← 服务器主动连客户端 (PORT)
[15] DATA [SYN+ACK] 10.0.0.1:20003→20.0.0.1:20
[16] DATA [ACK] 20.0.0.1:20→10.0.0.1:20003
[17] DATA [ACK+PSH] 20.0.0.1:20→10.0.0.1:20003 plen=118  ← 文件内容 (server→client, 下载)
[18-22] DATA [ACK/FIN 拆链]
────────── 数据面结束 ──────────
[23] CONTROL 226: 226 Transfer complete
[24-29] QUIT + 拆链
```

- **数据面 4-tuple**: `20.0.0.1:20 → 10.0.0.1:20003` (服务器从 port 20 主动连客户端 20003)
- **数据面 SYN 方向**: server→client (20.0.0.1 → 10.0.0.1)
- **位置**: ✅ PASS

### 3.4 FTP PORT STOR (上传) — `single-ftp-active-stor.pcap`

```
[ 0-12] 同上 (握手 + USER/PASS/TYPE/PORT/STOR)
[13] CONTROL 150: 150 Opening data connection
────────── 数据面 (20.0.0.1:20 → 10.0.0.1:20004) ──────────
[14] DATA [SYN] 20.0.0.1:20→10.0.0.1:20004       ← 服务器主动连 (PORT)
[15] DATA [SYN+ACK] 10.0.0.1:20004→20.0.0.1:20
[16] DATA [ACK] 20.0.0.1:20→10.0.0.1:20004
[17] DATA [ACK+PSH] 10.0.0.1:20004→20.0.0.1:20 plen=121  ← 文件内容 (client→server, 上传)
[18-22] DATA [ACK/FIN 拆链]
────────── 数据面结束 ──────────
[23] CONTROL 226: 226 Transfer complete
[24-29] QUIT + 拆链
```

- **数据面 4-tuple**: `20.0.0.1:20 → 10.0.0.1:20004`
- **位置**: ✅ PASS

---

## 4. SIP RTP 场景详细包序列 — `single-sip-rtp-g711.pcap`

```
[ 0] TCP [SYN]                       10.0.0.1:5060 → 20.0.0.1:5060
[ 1] TCP [SYN+ACK]
[ 2] TCP [ACK]
[ 3] TCP INVITE sip:callee@20.0.0.1 SIP/2.0  + SDP body (m=audio 5004 RTP/AVP 0)
[ 4] TCP 100 Trying
[ 5] TCP 180 Ringing
[ 6] TCP 200 OK                     + SDP body (callee 端口 5004)
[ 7] TCP ACK                          ← 信令面锚点 1 (RTP 开始)
────────── RTP 媒体面 (UDP 10.0.0.1:5004 → 20.0.0.1:5004) ──────────
[ 8] UDP RTP frame (V=2) 10.0.0.1:5004→20.0.0.1:5004   ← RTP #1
[ 9] UDP RTP frame (V=2)                                ← RTP #2
[10] UDP RTP frame (V=2)                                ← RTP #3
[11] UDP RTP frame (V=2)                                ← RTP #4
[12] UDP RTP frame (V=2)                                ← RTP #5
[13] UDP RTP frame (V=2)                                ← RTP #6
[14] UDP RTP frame (V=2)                                ← RTP #7
[15] UDP RTP frame (V=2)                                ← RTP #8
[16] UDP RTP frame (V=2)                                ← RTP #9
[17] UDP RTP frame (V=2)                                ← RTP #10
────────── RTP 结束 ──────────
[18] TCP BYE sip:callee@20.0.0.1      ← 信令面锚点 2 (RTP 应在此前结束)
[19] TCP 200 OK
[20-23] TCP [FIN/ACK 四步拆链]
```

- **RTP 帧**: 10 帧，端口 5004→5004 (UDP)
- **RTP 头**: byte0=0x80 (V=2, P=0, X=0, CC=0)，PT=0 (PCMU)
- **位置**: RTP [8-17] 完全嵌入 ACK [7] 和 BYE [18] 之间 ✅

---

## 5. SCTP 场景详细包序列

### 5.1 SCTP HEARTBEAT 单路径 — `single-sctp-hb-primary.pcap`

```
[ 0] SCTP INIT (1)         10.0.0.1→20.0.0.1
[ 1] SCTP INIT-ACK (2)     20.0.0.1→10.0.0.1
[ 2] SCTP COOKIE-ECHO (10) 10.0.0.1→20.0.0.1
[ 3] SCTP COOKIE-ACK (11)  20.0.0.1→10.0.0.1     ← 信令面锚点 (HB 开始)
[ 4] SCTP HB (4)            10.0.0.1→20.0.0.1     ← HB #1
[ 5] SCTP HB-ACK (5)        20.0.0.1→10.0.0.1     ← HB-ACK #1
[ 6] SCTP HB (4)            10.0.0.1→20.0.0.1     ← HB #2
[ 7] SCTP HB-ACK (5)        20.0.0.1→10.0.0.1
[ 8] SCTP HB (4)            10.0.0.1→20.0.0.1     ← HB #3
[ 9] SCTP HB-ACK (5)        20.0.0.1→10.0.0.1
[10] SCTP HB (4)            10.0.0.1→20.0.0.1     ← HB #4
[11] SCTP HB-ACK (5)        20.0.0.1→10.0.0.1
[12] SCTP HB (4)            10.0.0.1→20.0.0.1     ← HB #5
[13] SCTP HB-ACK (5)        20.0.0.1→10.0.0.1
[14] SCTP DATA (0)          10.0.0.1→20.0.0.1     ← 数据 chunk
[15] SCTP DATA (0)          20.0.0.1→10.0.0.1
[16] SCTP SHUTDOWN (7)     10.0.0.1→20.0.0.1
[17] SCTP SHUTDOWN-ACK (8) 20.0.0.1→10.0.0.1
[18] SCTP SHUTDOWN-COMPLETE (14) 10.0.0.1→20.0.0.1
```

- **HB 数**: 5 个 HB + 5 个 HB-ACK，交替
- **HB 路径**: 全部在主路径 10.0.0.1/20.0.0.1
- **位置**: 第一对 HB [4] 在 COOKIE-ACK [3] 之后 ✅

### 5.2 SCTP 多归属 (multi-homing) — `single-sctp-multihoming.pcap`

```
[ 0] SCTP INIT (1)         10.0.0.1→20.0.0.1     ← 主路径建立
[ 1] SCTP INIT-ACK (2)     20.0.0.1→10.0.0.1
[ 2] SCTP COOKIE-ECHO (10) 10.0.0.1→20.0.0.1
[ 3] SCTP COOKIE-ACK (11)  20.0.0.1→10.0.0.1     ← 锚点
[ 4] SCTP HB (4)            10.0.0.2→20.0.0.2     ← HB #1 走备路径
[ 5] SCTP HB-ACK (5)        20.0.0.2→10.0.0.2
[ 6] SCTP HB (4)            10.0.0.2→20.0.0.2     ← HB #2 备路径
[ 7] SCTP HB-ACK (5)        20.0.0.2→10.0.0.2
[ 8] SCTP HB (4)            10.0.0.2→20.0.0.2
[ 9] SCTP HB-ACK (5)        20.0.0.2→10.0.0.2
[10] SCTP HB (4)            10.0.0.2→20.0.0.2
[11] SCTP HB-ACK (5)        20.0.0.2→10.0.0.2
[12] SCTP HB (4)            10.0.0.2→20.0.0.2     ← HB #5
[13] SCTP HB-ACK (5)        20.0.0.2→10.0.0.2
[14] SCTP DATA (0)          10.0.0.1→20.0.0.1     ← 数据走主路径
[15] SCTP SHUTDOWN (7)     10.0.0.1→20.0.0.1
[16] SCTP SHUTDOWN-ACK (8) 20.0.0.1→10.0.0.1
[17] SCTP SHUTDOWN-COMPLETE (14) 10.0.0.1→20.0.0.1
```

- **HB 路径**: 5 个 HB 全部在备路径 10.0.0.2/20.0.0.2（不同 IP）
- **DATA 路径**: 主路径 10.0.0.1/20.0.0.1
- **位置**: HB 在 COOKIE-ACK 之后，DATA 之前 ✅

---

## 6. 文件清单（本地保存）

| 文件 | 用途 |
|------|------|
| `/tmp/mcp-pcaps/single-ftp-pasv-retr.json` | FTP PASV RETR 场景 spec |
| `/tmp/mcp-pcaps/single-ftp-pasv-retr.pcap` | FTP PASV RETR 场景 pcap (30 包) |
| `/tmp/mcp-pcaps/single-ftp-pasv-stor.json` | FTP PASV STOR 场景 spec |
| `/tmp/mcp-pcaps/single-ftp-pasv-stor.pcap` | FTP PASV STOR 场景 pcap (30 包) |
| `/tmp/mcp-pcaps/single-ftp-active-retr.json` | FTP PORT RETR 场景 spec |
| `/tmp/mcp-pcaps/single-ftp-active-retr.pcap` | FTP PORT RETR 场景 pcap (30 包) |
| `/tmp/mcp-pcaps/single-ftp-active-stor.json` | FTP PORT STOR 场景 spec |
| `/tmp/mcp-pcaps/single-ftp-active-stor.pcap` | FTP PORT STOR 场景 pcap (30 包) |
| `/tmp/mcp-pcaps/single-sip-rtp-g711.json` | SIP RTP G.711 场景 spec |
| `/tmp/mcp-pcaps/single-sip-rtp-g711.pcap` | SIP RTP G.711 场景 pcap (24 包) |
| `/tmp/mcp-pcaps/single-sctp-hb-primary.json` | SCTP 单路径 HB 场景 spec |
| `/tmp/mcp-pcaps/single-sctp-hb-primary.pcap` | SCTP 单路径 HB 场景 pcap (19 包) |
| `/tmp/mcp-pcaps/single-sctp-multihoming.json` | SCTP 多归属场景 spec |
| `/tmp/mcp-pcaps/single-sctp-multihoming.pcap` | SCTP 多归属场景 pcap (18 包) |
| `/tmp/mcp-pcaps/verify_single_scenarios.py` | Python 解析+验证脚本 |
| `/tmp/mcp-pcaps/verify_single_output.txt` | 验证脚本输出 (277 行) |
| `/home/weihang/trafficGenerator/trafficgen/docs/multiflow-scenarios-pcap.md` | 本文文档 |

---

## 7. 组合多流 pcap（之前已有，作为综合测试）

| pcap 文件 | 场景 | 包数 | 流数 | 说明 |
|----------|------|------|------|------|
| `/tmp/mcp-pcaps/ftp-multiflow.pcap` | FTP 4 场景组合 | 120 | 8 | 4 控制面 + 4 数据面 |
| `/tmp/mcp-pcaps/sip-rtp.pcap` | SIP 1 场景 | 24 | 2 | TCP + UDP |
| `/tmp/mcp-pcaps/sctp-hb.pcap` | SCTP 2 场景组合 | 37 | 37 chunks | 主+备路径 |

组合 pcap 用于端到端综合验证，单项 pcap 用于定位问题。两套都保留。

---

## 8. 重跑验证命令

```bash
# 重新解析所有单项 pcap 并验证位置
cd /tmp/mcp-pcaps && python3 verify_single_scenarios.py | tee verify_single_output.txt

# 用 Wireshark 单独打开某个场景
wireshark /tmp/mcp-pcaps/single-ftp-pasv-retr.pcap
wireshark /tmp/mcp-pcaps/single-sip-rtp-g711.pcap
wireshark /tmp/mcp-pcaps/single-sctp-multihoming.pcap

# 重新生成某个单项 pcap（需要 flowB MCP server 运行）
# 用 mcp__flowb__flowb_generate_traffic 提交 spec，output_type=pcap
```

---

## 9. 代码修复历史（2026-07-24）

本批 pcap 生成过程中发现并修复的代码问题：

| 修复 | 文件 | 说明 |
|------|------|------|
| FTP PASV/PORT 端口解析 | `internal/protocol/ftp/ftp.go` | 从 227 PASV 响应/PORT 命令解析数据面端口，避免与信令面端口不一致 |
| FTP PORT 命令大小写不敏感 | `internal/protocol/ftp/ftp.go` | `portCmdRe` 加 `(?i)` 标志，匹配 RFC 959 §5.3.1 |
| SIP SDP 媒体端口解析 | `internal/protocol/sip/sip.go` | 从 INVITE/200 OK 的 SDP `m=audio` 行解析 RTP 端口 |
| SCTP INIT/INIT-ACK 多归属地址参数 | `internal/protocol/sctp/sctp.go` | 按 RFC 4960 §3.3.2 在 INIT 携带客户端备地址、INIT-ACK 携带服务器备地址 |
| SCTP INIT-ACK 端口对调 | `internal/protocol/sctp/sctp.go` | server->client 包的 srcPort/dstPort 之前对调了，已修正为 `spec.DstPort, spec.SrcPort` |

提交记录：
- `0b12756` fix(ftp,sip,sctp): parse data-plane ports from signaling messages
- `624cff2` fix(ftp,sctp): PORT case-insensitivity + SCTP INIT-ACK port swap


# #103 ftp（RFC 959 + RFC 2428）测试用例契约

> 版本：v1.0.0（P-PIPE 文档轨批次二 · as-built 契约）
> 日期：2026-09-29
> 配套设计：`docs/protocol-designs/103-ftp-design.md` v1.0.0（D-FTP-1）
> 旧基线：**无**（本仓从无 ftp 设计/用例文档，机读实测；本对为首份）
> 机器契约：`trafficgen/test/protocol_pcap/cases/ftp.json`（**141 例 = 136 正 + 5 负**，ID 集合/顺序/包数/断言与本版 §2 **逐条一致**，已机读实测）
> 白话一句：**一百四十一条检查：一百三十六条看正常收发（登录、传文件、列目录、续传、追加、扩展模式、失败应答、多会话、多流、IPv6），五条看配置写错能不能被拦下；每条只查一件事。**

## 1. 测试原则和形状基线

用例从设计 §3–§9 逐项派生。派生规则：设计 §3 每条线格式/端口推导条款、§5 每个事务/自动派生行为、§6 每个流关联面、§7 每行错误处理在本文有对应断言；断言不得超出设计声明范围。**一个用例只验证一个协议行为**。

**形状基线（2026-09-29 机读实测）**：

| 项 | 实测值 |
|---|---|
| 例数 | **141**（136 正 + 5 负） |
| 顶层键 | `{expect,id,proto,spec_json,summary}` ×85 + `{…, strategy_fc}` ×56 —— **`spec_json` 顶层键 = `{layers}` ×141（唯一键，零游离键、零顶层 `ftp` 子映射）** |
| 层形 | `[ip,tcp,ftp]` ×110 + `[tcp,ftp]` ×31 |
| `strategy_fc` | 51 例（全 `type=flows`；值域 `{2:9, 3:38, 4:2, 100:1, 1000:1}`） |
| IPv6 例 | **12**（`ip.src/dst` 写 v6 字面量） |
| `expect` 键 | 正例 136：`min_packets` ×136、`packet_count` ×104、`negotiated` ×136、`terminates` ×136、`has_handshake` ×101、`has_payload` ×47、`fields` ×122、`frames` ×1、`notes` ×136；负例 5：`{expect_error, error_contains, notes}` ×5 |
| 断言条数 | `fields` **331** 条（122 例）+ `frames` **3** 条（1 例）+ `distinct_values` **58** 条 |
| 字段通道直方图 | `ftp.request.command` 99 / `ftp.response.code` 94 / `tcp.srcport` 44 / `ftp.request.arg` 42 / `tcp.dstport` 31 / `ftp.response.arg` 6 / `ipv6.src` 5 / `ip.src` 4 / `ipv6.dst` 3 / `ip.dst` 3 |

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`tcp.srcport/dstport`、`tcp.flags`、`ftp.request.command/arg`、`ftp.response.code/arg`、`ip.src/dst`、`ipv6.src/dst`、offset 54/74 frames）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；不设仅单路径可用的断言。

**TSHARK 基线（实测）**：本机 tshark **3.6.14 有 ftp dissector**——`tshark -G fields | awk '$3 ~ /^ftp\./'` = **33 字段**；`tshark -G decodes` 有 `tcp.port 21 ftp` 与 `tcp.port 20 ftp-data`。**存量只用其中 4 个**（`ftp.request.command`/`ftp.request.arg`/`ftp.response.code`/`ftp.response.arg`）→ **29 个零使用**（33 总 − 4 已用）（含 `ftp.setup-frame`/`ftp.command-response.frames`/`ftp.passive.port`/`ftp.epsv.port`/`ftp.eprt.af` 等）→ A′ 立项（设计 G-FTP-8）。

**断言基线**：136 正例全部有 `packet_count` 或 `min_packets` + `negotiated` + `terminates`；122 例有字段级断言；**只有 1 例有 frame hex 断言**（`ftp_smoke_01`，3 条）。

**包数对账（§9.1 详表）**：**真实 pcap 帧数 == 结果产物包数 = 138/138 一致**；`packet_count == min_packets` **104/104**；`packet_count == 真实帧数` **104/104**；`min_packets <= 真实帧数` **136/136**。**本协议包数三方零冲突**（与 opcua 的"包数全错"对照）。**但"三方一致 ≠ 语义正确"**：`ftp_file_source`/`ftp_file_source_abort`（载荷静默不发，G-FTP-2）与 `ftp_multiflow_multisession`（会话合并，G-FTP-3）三方都一致。

**保活/重试/RST 口径**：协议层**无保活定时器**（`NOOP` 只是普通命令，`ftp_min_noop`）；**无重试/重连语义**（生成器不回放重传）；**RST 为框架 tcp 层能力，本协议层零断言**（141 例全部 FIN 优雅终止，`terminates=true` 136/136）。**RFC 2428 的 500/522 拒绝**是**应答码层面的拒绝**（不是配置拒绝，`ftp_epsv_500_fallback`/`ftp_eprt_522_reject` 是**正例**，14 帧正常收发）。

## 2. 原子用例索引（141 ID = 136 正 + 5 负，顺序为权威）

**包数列**：有 `packet_count` 的写 JSON 值；只有 `min_packets` 的写「N（实测）」（N = 结果产物包数 = 真实 pcap 帧数，138 例已逐条复核）。**断言列**：`pc` = packet_count/min_packets；`fields×N` / `frames×N` / `distinct×N`；`hs` = has_handshake；`pl` = has_payload。

| # | ID | 类型 | 场景（summary 原文） | 包数 | 断言 |
|---:|---|---|---|---:|---|
| 1 | `ftp_smoke_01` | 正 | FTP 控制通道冒烟（层链 [ip,tcp,ftp]）：USER/PASS/QUIT（RFC 959 §4.1），14 帧 = 3 握手 + banner + 3 命令×2 + 4 终止 | 14（实测） | pc=14 + fields×11 + frames×3 |
| 2 | `ftp_retr_passive` | 正 | T-FTP-2: PASV+RETR 下载（层链），数据通道挂载在 150 与 226 之间；28 帧 = 控制通道 19 + 数据通道 9 | 27 | pc=27 + fields×9 + hs + pl |
| 3 | `ftp_stor_upload` | 正 | T-FTP-2b: PORT+STOR 上传（层链），数据方向=up（client→server）；28 帧 | 27 | pc=27 + fields×6 + hs + pl |
| 4 | `ftp_sessions_dual` | 正 | T-FTP-2 sessions: 双会话（RETR+LIST，层链），独立 TCP 连接、独立数据通道 | 46 | pc=46 + fields×2 + hs + pl |
| 5 | `ftp_txindex_dual` | 正 | T-FTP-3: 单会话双事务（层链），两条数据流各取本事务 PASV 端口 50011/50012 | 32 | pc=32 + fields×3 + hs + pl |
| 6 | `ftp_pasv_isolation` | 正 | T-FTP-4: 后事务数据流取本事务 PASV 端口（层链），不串前事务 49993 | 32 | pc=32 + fields×3 + hs + pl |
| 7 | `ftp_empty_session` | 正 | T-FTP-5: 空会话合法（层链）——仅握手 3 + 挥手 4 = 7 包，连接端口 = 会话 src_port | 7 | pc=7 + fields×2 |
| 8 | `ftp_noflag_no_subflow` | 正 | T-FTP-6: 事务有 DataChannel 但无 emit 标记（层链）→ 不发射子流 | 9 | pc=9 + fields×2 |
| 9 | `ftp_session_dynamic_ports` | 正 | T-FTP-10: 会话 src_port_dyn inc [20000..20003]（层链），4 流各不同端口；48 帧 = 4×12 | 48 | pc=48 + fields×1 + pl + distinct×1 |
| 10 | `ftp_dyn_command_pattern` | 正 | T-FTP-11: cmd_dyn pattern 逐流动态（层链），RETR 文件名按流变；46 帧 = 2×23 | 44 | pc=44 + fields×1 + pl |
| 11 | `ftp_dyn_payload` | 正 | T-FTP-12: data_channel payload_dyn pattern 逐流动态（层链）；46 帧 = 2×23 | 44 | pc=44 + fields×1 + pl |
| 12 | `ftp_response_dyn` | 正 | T-FTP-11b: response_dyn pattern 逐流动态（层链），331/332 文本按流变 | 22 | pc=22 + fields×2 + pl |
| 13 | `ftp_banner_dyn_list` | 正 | T-FTP-10b: banner_dyn list 逐流轮转（层链），220 横幅按流变 | 20 | pc=20 + fields×1 + pl |
| 14 | `ftp_multi_command` | 正 | 多命令无数据通道（层链）：6 命令全双包，20 帧 = 3 握手 + banner + 6×2 + 4 终止 | 20 | pc=20 + fields×3 + pl |
| 15 | `ftp_mss_segmentation` | 正 | MSS 分段（层链）：超长 payload 触发 tcp 层默认 MSS=1460 分段，数据通道段数随 payload 长度增长 | 28（实测） | pc=28 + fields×2 + hs + pl |
| 16 | `ftp_neg_static_copy` | 负 | 层链静态复制拒绝：ip/tcp 层显式标量四元组 + flows>1 → 400 static four-tuple（Task 5 后扁平已死，负例改层链锚词） | —（0 帧） | `expect_error`+`error_contains` |
| 17 | `ftp_neg_mss_too_small` | 负 | MSS<536 拒绝（层链）：tcp 层 mss=100 → V9 范围拒绝（RFC 879 最小 536） | —（0 帧） | `expect_error`+`error_contains` |
| 18 | `ftp_neg_dyn_no_range` | 负 | 动态策略 inc 无 range（层链）→ 任务启动 validateDynFields 拒绝 | —（0 帧） | `expect_error`+`error_contains` |
| 19 | `ftp_neg_session_static_copy` | 负 | 会话静态复制拒绝（层链）：两个会话固定 src_port + flows>1 → 任务启动 validateSessionStaticCopy 拒绝 | —（0 帧） | `expect_error`+`error_contains` |
| 20 | `ftp_perf_100flows` | 正 | 性能测试（层链）：100 流 × USER/PASS/QUIT = 1400 帧，验证吞吐无异常 | 1400 | pc=1400 + fields×1 + pl + distinct×1 |
| 21 | `ftp_perf_1000flows` | 正 | 性能压力测试（层链）：1000 流 × USER/PASS/QUIT = 14000 帧 | 14000 | pc=14000 + fields×1 + pl + distinct×1 |
| 22 | `ftp_min_noop` | 正 | RFC 959 §5.1 最小实现：NOOP→200（无参数无动作） | 16 | pc=16 + fields×3 + pl |
| 23 | `ftp_min_stru` | 正 | RFC 959 §5.1/§4.1.2 STRU R 记录结构（最小实现成员） | 16 | pc=16 + fields×3 + pl |
| 24 | `ftp_min_mode` | 正 | RFC 959 §5.1/§4.1.2 MODE S 流模式（最小实现成员） | 16 | pc=16 + fields×3 + pl |
| 25 | `ftp_type_ascii` | 正 | RFC 959 §4.1.2 TYPE A ASCII 默认类型 + A N 格式参数 | 18 | pc=18 + fields×5 + pl |
| 26 | `ftp_type_local` | 正 | RFC 959 §4.1.2 TYPE L 8 本地字节类型（必带第二参数） | 16 | pc=16 + fields×3 + pl |
| 27 | `ftp_type_image` | 正 | RFC 959 §4.1.2 TYPE I Image 二进制（最小实现成员） | 16 | pc=16 + fields×3 + pl |
| 28 | `ftp_login_acct` | 正 | RFC 959 §4.1.1/§5.4 需账户登录：USER→331→PASS→332→ACCT→230 | 16 | pc=16 + fields×6 + pl |
| 29 | `ftp_login_530` | 正 | RFC 959 §4.2.1/§5.4 认证失败：PASS→530 Not logged in | 14 | pc=14 + fields×3 + pl |
| 30 | `ftp_login_rein` | 正 | RFC 959 §4.1.1 REIN 重初始化：登录→REIN→220→重新登录 | 20 | pc=20 + fields×6 + pl |
| 31 | `ftp_login_reuser` | 正 | RFC 959 §4.1.1 中途 re-USER：冲掉已供凭证重新登录 | 18 | pc=18 + fields×4 + pl |
| 32 | `ftp_login_nobanner` | 正 | RFC 959 §5.4 banner 缺席：握手后直发 USER | 13 | pc=13 + fields×2 + pl |
| 33 | `ftp_rnfr_rnto` | 正 | RFC 959 §4.1.3/§5.4 改名序列：RNFR→350→RNTO→250（350 中间态） | 18 | pc=18 + fields×4 + pl |
| 34 | `ftp_file_mgmt` | 正 | RFC 959 §4.1.3 文件管理四连：MKD 257/PWD 257/RMD 250/DELE 250 | 22 | pc=22 + fields×8 + pl |
| 35 | `ftp_cdup` | 正 | RFC 959 §4.1.1 CDUP 切父目录（CWD 特例，响应码同 CWD 家族） | 18 | pc=18 + fields×3 + pl |
| 36 | `ftp_smnt` | 正 | RFC 959 §4.1.1 SMNT 结构挂载：SMNT→250 | 16 | pc=16 + fields×3 + pl |
| 37 | `ftp_syst` | 正 | RFC 959 §4.1.3 SYST 系统类型：215 UNIX Type: L8 | 16 | pc=16 + fields×3 + pl |
| 38 | `ftp_help` | 正 | RFC 959 §4.1.3 HELP（RFC 允许 USER 之前调用）：214 | 16 | pc=16 + fields×3 + pl |
| 39 | `ftp_stat` | 正 | RFC 959 §4.1.3 STAT 传输间状态查询（控制连接回复 211） | 16 | pc=16 + fields×3 + pl |
| 40 | `ftp_site` | 正 | RFC 959 §4.1.3 SITE 站点参数（服务器特定）：200 | 16 | pc=16 + fields×3 + pl |
| 41 | `ftp_transfer_450` | 正 | RFC 959 §5.4 RETR→450 文件不可用（无数据通道发射） | 18 | pc=18 + fields×4 + pl |
| 42 | `ftp_stor_550` | 正 | RFC 959 §7 官方示例场景：STOR→550 Access denied→QUIT（拒绝后退出） | 18 | pc=18 + fields×4 + pl |
| 43 | `ftp_dataconn_425` | 正 | RFC 959 §4.2.1/§5.4 数据连接失败：425 Can't open data connection | 18 | pc=18 + fields×4 + pl |
| 44 | `ftp_badseq_503` | 正 | RFC 959 §5.4 坏序列：无登录直接 RETR→503 Bad sequence | 16 | pc=16 + fields×3 + pl |
| 45 | `ftp_stou` | 正 | RFC 959 §4.1.3 STOU 唯一存储：125 已开数据连接变体 + 上传 | 29 | pc=29 + fields×5 + hs + pl |
| 46 | `ftp_appe` | 正 | RFC 959 §4.1.3 APPE 追加存储：150→数据→226（被动上传） | 29 | pc=29 + fields×5 + hs + pl |
| 47 | `ftp_rest_retr` | 正 | RFC 959 §4.1.3 REST 断点续传：REST→350→PASV→RETR（服务端续传点） | 31 | pc=31 + fields×6 + hs + pl |
| 48 | `ftp_nlst` | 正 | RFC 959 §4.1.3 NLST 名单列表（纯文件名流，区别于 LIST 详情） | 27 | pc=27 + fields×5 + hs + pl |
| 49 | `ftp_allo_stor` | 正 | RFC 959 §4.1.3 ALLO 预分配（含 R 双参数）→202→PASV→STOR | 29 | pc=29 + fields×6 + hs + pl |
| 50 | `ftp_dataconn_250` | 正 | RFC 959 §3.2/§5.4 完成码 250 变体：LIST→150→数据→250（226 的合法替代） | 27 | pc=27 + fields×5 + hs + pl |
| 51 | `ftp_dataconn_125` | 正 | RFC 959 §4.2.1 125 已开数据连接变体（150 替代）+226 | 27 | pc=27 + fields×5 + hs + pl |
| 52 | `ftp_port_pasv_dual` | 正 | RFC 959 §3.3 PORT+PASV 双协商：两端都声明非默认端口（最终走 passive） | 29 | pc=29 + fields×6 + hs + pl |
| 53 | `ftp_dataconn_fallback` | 正 | RFC 959 §3.2 端口推导回退：无 PASV/PORT 信令→server 50000 | 25 | pc=25 + fields×5 + hs + pl |
| 54 | `ftp_dataconn_explicit_ports` | 正 | RFC 959 端口推导最高优先级：显式 src/dst 覆盖 PASV 信令 | 27 | pc=27 + fields×5 + hs + pl |
| 55 | `ftp_abor_completed` | 正 | RFC 959 §4.1.3 ABOR 情形①：传输已完成→226（无 426） | 31 | pc=31 + fields×6 + hs + pl |
| 56 | `ftp_abor_midtransfer` | 正 | RFC 959 §4.1.3/§5.4 ABOR 情形②：传输中中断→426+226 双响应（abort_after_bytes 截断） | 31 | pc=31 + fields×6 + hs + pl |
| 57 | `ftp_abor_idle` | 正 | RFC 959 §5.4 ABOR 空闲：无进行中传输→225 Data connection open | 16 | pc=16 + fields×3 + pl |
| 58 | `ftp_passive_stor` | 正 | 组合：被动模式上传（PASV+STOR direction=up，client 首 SYN） | 29 | pc=29 + fields×5 + hs + pl |
| 59 | `ftp_active_retr` | 正 | 组合：主动模式下载（PORT+RETR direction=down，server 20 首 SYN） | 29 | pc=29 + fields×5 + hs + pl |
| 60 | `ftp_active_appe` | 正 | 组合：主动模式追加（PORT+APPE direction=up） | 29 | pc=29 + fields×5 + hs + pl |
| 61 | `ftp_payload_b64` | 正 | PayloadB64 二进制载荷：base64 解码后上路（含 NUL 字节） | 27 | pc=27 + fields×5 + hs + pl |
| 62 | `ftp_abort_bytes` | 正 | AbortAfterBytes 截断：1024 字节 payload 只发前 10 字节 | 27 | pc=27 + fields×4 + hs + pl |
| 63 | `ftp_file_source` | 正 | FileSource literal 文件读取：数据通道载荷来自 file_source | 26（实测） | pc=26 + fields×2 + hs + pl |
| 64 | `ftp_port_overflow` | 正 | RFC 959 §3.2 ctrlPort=65535 溢出守卫：客户端口回退 1024（不回绕 0） | 25 | pc=25 + fields×5 + hs + pl |
| 65 | `ftp_ipv6_data` | 正 | IPv6 全程含被动下载：ip 层 2001:db8::/32 + PASV+RETR 数据通道 | 29 | pc=29 + fields×5 + hs + pl |
| 66 | `ftp_3sessions_mixed` | 正 | 3 会话混合操作：会话1 无事务（空）+会话2 RETR+会话3 LIST，独立端口/序号 | 61（实测） | pc=61 + fields×1 + hs + pl + distinct×1 |
| 67 | `ftp_multiflow_data` | 正 | 多流×数据通道组合：flows=3 每流 PASV+RETR 含独立数据通道（端口逐流隔离） | 72（实测） | pc=72 + fields×1 + hs + pl + distinct×1 |
| 68 | `ftp_retr_550_notfound` | 正 | RFC 959 §5.4 RETR→550 文件不存在（fail 分支，无数据通道） | 18 | pc=18 + fields×4 + pl |
| 69 | `ftp_stor_532_nospace` | 正 | RFC 959 §5.4 STOR→532 存储空间不足（fail 分支） | 18 | pc=18 + fields×4 + pl |
| 70 | `ftp_rnfr_450_fail` | 正 | RFC 959 §5.4 RNFR→450 改名源文件忙（fail 分支，无 RNTO） | 16 | pc=16 + fields×3 + pl |
| 71 | `ftp_dele_550_fail` | 正 | RFC 959 §5.4 DELE→550 删除被拒（fail 分支） | 16 | pc=16 + fields×3 + pl |
| 72 | `ftp_cwd_550_fail` | 正 | RFC 959 §5.4 CWD→550 目录不存在（fail 分支） | 16 | pc=16 + fields×3 + pl |
| 73 | `ftp_login_530_cmd` | 正 | RFC 959 §5.4 未登录发命令→530（USER 前 RETR 之外的 530 家族） | 14 | pc=14 + fields×3 + pl |
| 74 | `ftp_syntax_500` | 正 | RFC 959 §4.2/§5.4 语法错误命令→500（syntax 家族代表：未知命令） | 16 | pc=16 + fields×3 + pl |
| 75 | `ftp_arg_501` | 正 | RFC 959 §4.2 TYPE 参数非法→501（syntax 家族：参数错误） | 16 | pc=16 + fields×3 + pl |
| 76 | `ftp_service_421` | 正 | RFC 959 §4.2 服务端超时 421：命令响应后连接将关闭（会话中途服务不可用） | 14 | pc=14 + fields×3 + pl |
| 77 | `ftp_list_226_success` | 正 | RFC 959 §5.4 LIST→150→数据→226 成功完成（success 分支，补 226） | 27 | pc=27 + fields×5 + hs + pl |
| 78 | `ftp_nlst_226_success` | 正 | RFC 959 §5.4 NLST→150→数据→226 名单成功完成 | 27 | pc=27 + fields×5 + hs + pl |
| 79 | `ftp_sessions_mixed_mode` | 正 | 组合：双会话跨模式（会话1 passive 下载 + 会话2 active 上传） | 46 | pc=46 + fields×2 + hs + pl |
| 80 | `ftp_ipv6_active` | 正 | 组合：IPv6 + active 模式上传（ip 层 v6 + PORT+STOR server 首 SYN） | 27 | pc=27 + fields×4 + hs + pl |
| 81 | `ftp_session_partial_data_tx` | 正 | 组合：单会话 3 事务，仅第 2 事务挂数据通道（部分发射） | 29 | pc=29 + fields×2 + hs + pl |
| 82 | `ftp_rest_stor_upload` | 正 | 组合：REST 续传 + STOR 上传续传（REST→350→PASV→STOR→数据） | 31 | pc=31 + fields×6 + hs + pl |
| 83 | `ftp_abor_active_mode` | 正 | 组合：ABOR 中断主动模式上传（PORT+STOR active，426+226 双响应） | 31 | pc=31 + fields×6 + hs + pl |
| 84 | `ftp_file_source_abort` | 正 | 组合：FileSource 文件读取 + AbortAfterBytes 截断 | 26 | pc=26 + fields×3 + hs + pl |
| 85 | `ftp_multiflow_multisession` | 正 | 组合：多流×多会话×数据通道（flows=2，每流 2 会话各挂数据通道） | 70 | pc=70 + fields×1 + hs + pl + distinct×1 |
| 86 | `ftp_stat_213_file` | 正 | RFC 959 §4.2.1 STAT 带路径参数→213 File status（数据经控制连接） | 16（实测） | pc=16 + fields×1 + pl |
| 87 | `ftp_stat_212_dir` | 正 | RFC 959 §4.2.1 STAT 目录→212 Directory status | 16（实测） | pc=16 + fields×1 + pl |
| 88 | `ftp_retr_110_marker` | 正 | RFC 959 §4.2.1/§3.4.2 110 Restart marker（Block 模式传输中响应，文本必须 'MARK yyyy = mmmm'） | 25 | pc=25 + fields×4 + pl |
| 89 | `ftp_banner_120_greeting` | 正 | RFC 959 §5.4/§4.2.1 延迟问候：banner 120 Service ready in 5 minutes（后再 220） | 13（实测） | pc=13 + fields×1 + pl |
| 90 | `ftp_transfer_451_localerr` | 正 | RFC 959 §4.2.1 451 本地处理错误（transient 分支）：RETR→150→451（服务器内部错误中断） | 18（实测） | pc=18 + fields×1 + pl |
| 91 | `ftp_stor_452_quota` | 正 | RFC 959 §4.2.1 STOR→452 存储配额不足（fail 分支，区别 532 账户） | 18（实测） | pc=18 + fields×1 + pl |
| 92 | `ftp_stor_552_exceedalloc` | 正 | RFC 959 §4.2.1 STOR→552 超出存储分配（transient） | 18（实测） | pc=18 + fields×1 + pl |
| 93 | `ftp_stor_553_filename` | 正 | RFC 959 §4.2.1 STOR→553 文件名不允许（fail） | 18（实测） | pc=18 + fields×1 + pl |
| 94 | `ftp_stor_551_pagetype` | 正 | RFC 959 §4.2.1 STOR→551 页类型未知（transient，页结构场景） | 20（实测） | pc=20 + fields×1 + pl |
| 95 | `ftp_502_notimpl` | 正 | RFC 959 §4.2.1 502 命令未实现（SITE 站点命令不支持） | 15（实测） | pc=15 + fields×1 + pl |
| 96 | `ftp_type_504_badparam` | 正 | RFC 959 §4.2.1 TYPE→504 参数未实现（如 TYPE E EBCDIC 在纯 ASCII 服务器） | 15（实测） | pc=15 + fields×1 + pl |
| 97 | `ftp_dc_mss_override` | 正 | dc.mss 数据通道级 MSS 覆盖（B 类缺口钉现状）：链路径当前忽略该字段、按链全局 MSS=1460 分段 | 28（实测） | pc=28 + fields×1 + hs + pl |
| 98 | `ftp_dyn_ip_src_inc` | 正 | 层字段动态 ip.src inc：3 流源地址 10.0.1.1→3 递增（D-FTP-3） | 27 | pc=27 + fields×1 + hs + pl + distinct×1 |
| 99 | `ftp_dyn_ip_dst_inc` | 正 | 层字段动态 ip.dst inc：3 流目的地址 20.0.1.1→3 递增 | 27 | pc=27 + fields×1 + hs + pl + distinct×1 |
| 100 | `ftp_dyn_ip_src_rand` | 正 | 层字段动态 ip.src rand seed=7：同 seed 可复现，3 流值首跑钉 | 27 | pc=27 + fields×1 + hs + pl + distinct×1 |
| 101 | `ftp_dyn_ip_src_list` | 正 | 层字段动态 ip.src list 轮转：3 流取 list[0..2] | 27 | pc=27 + fields×1 + hs + pl + distinct×1 |
| 102 | `ftp_dyn_ip_src_fixed` | 正 | 层字段动态 ip.src fixed：动态对象写常量 10.0.4.1（解析分支） | 27 | pc=27 + fields×1 + hs + pl + distinct×1 |
| 103 | `ftp_dyn_ip_dst_rand` | 正 | 层字段动态 ip.dst rand seed=7：同 seed 可复现 | 27 | pc=27 + fields×1 + hs + pl + distinct×1 |
| 104 | `ftp_dyn_ip_dst_fixed` | 正 | 层字段动态 ip.dst fixed 常量 | 27 | pc=27 + fields×1 + hs + pl + distinct×1 |
| 105 | `ftp_dyn_tcp_srcport_inc` | 正 | 层字段动态 tcp.src_port inc：3 流 15200→15202 | 21（实测） | pc=21 + fields×1 + pl + distinct×1 |
| 106 | `ftp_dyn_tcp_srcport_rand` | 正 | 层字段动态 tcp.src_port rand seed=7 | 21（实测） | pc=21 + fields×1 + pl + distinct×1 |
| 107 | `ftp_dyn_tcp_srcport_list` | 正 | 层字段动态 tcp.src_port list 轮转 | 21（实测） | pc=21 + fields×1 + pl + distinct×1 |
| 108 | `ftp_dyn_tcp_srcport_fixed` | 正 | 层字段动态 tcp.src_port fixed 常量+inc dst_port 防撞 | 21（实测） | pc=21 + fields×1 + pl + distinct×1 |
| 109 | `ftp_dyn_tcp_dstport_inc` | 正 | 层字段动态 tcp.dst_port inc：3 流 212→214（非 21 服务口） | 21（实测） | pc=21 + fields×1 + pl + distinct×1 |
| 110 | `ftp_dyn_tcp_dstport_rand` | 正 | 层字段动态 tcp.dst_port rand seed=7 | 21（实测） | pc=21 + fields×1 + pl + distinct×1 |
| 111 | `ftp_dyn_neg_port_pattern` | 负 | 负例：tcp.src_port 写 pattern（端口算法不支持 pattern）→ 拒绝 | —（0 帧） | `expect_error`+`error_contains` |
| 112 | `ftp_dyn_sessport_rand` | 正 | 会话 src_port rand seed=7：3 流随机端口可复现 | 27 | pc=27 + fields×1 + pl + distinct×1 |
| 113 | `ftp_dyn_sessport_list` | 正 | 会话 src_port list 轮转：3 流 33101/33102/33103 | 27 | pc=27 + fields×1 + pl + distinct×1 |
| 114 | `ftp_dyn_sessport_fixed` | 正 | 会话 src_port fixed 常量 33200（动态对象豁免静态复制） | 27 | pc=27 + fields×1 + pl + distinct×1 |
| 115 | `ftp_dyn_sessport_wraparound` | 正 | 会话 src_port inc 回绕：range[33300,33301] flows=4 → 33300,33301,33300,33301 | 36 | pc=36 + fields×1 + pl + distinct×1 |
| 116 | `ftp_dyn_banner_inc` | 正 | 会话 banner inc：横幅数值递增逐流变 | 30 | pc=30 + fields×1 + pl |
| 117 | `ftp_dyn_banner_rand` | 正 | 会话 banner rand seed=7 | 30 | pc=30 + fields×1 + pl |
| 118 | `ftp_dyn_banner_fixed` | 正 | 会话 banner fixed 常量 | 30 | pc=30 + fields×1 + pl |
| 119 | `ftp_dyn_banner_pattern` | 正 | 会话 banner pattern 模板：220 host-{n} 逐流 | 30 | pc=30 + fields×1 + pl |
| 120 | `ftp_dyn_cmd_inc` | 正 | 会话 cmd_dyn inc（D-FTP-2 字符串策略补齐） | 27 | pc=27 + fields×1 + pl |
| 121 | `ftp_dyn_cmd_rand` | 正 | 会话 cmd_dyn rand（D-FTP-2 字符串策略补齐） | 27 | pc=27 + fields×1 + pl |
| 122 | `ftp_dyn_cmd_list` | 正 | 会话 cmd_dyn list（D-FTP-2 字符串策略补齐） | 27 | pc=27 + fields×1 + pl |
| 123 | `ftp_dyn_cmd_fixed` | 正 | 会话 cmd_dyn fixed（D-FTP-2 字符串策略补齐） | 27 | pc=27 + fields×1 + pl |
| 124 | `ftp_dyn_resp_inc` | 正 | 会话 response_dyn inc | 27 | pc=27 + fields×1 + pl |
| 125 | `ftp_dyn_resp_rand` | 正 | 会话 response_dyn rand | 27 | pc=27 + fields×1 + pl |
| 126 | `ftp_dyn_resp_list` | 正 | 会话 response_dyn list | 27 | pc=27 + fields×1 + pl |
| 127 | `ftp_dyn_resp_fixed` | 正 | 会话 response_dyn fixed | 27 | pc=27 + fields×1 + pl |
| 128 | `ftp_dyn_payload_inc` | 正 | 会话 payload_dyn inc（数据通道载荷策略补齐） | 60 | pc=60 + fields×1 + pl |
| 129 | `ftp_dyn_payload_rand` | 正 | 会话 payload_dyn rand（数据通道载荷策略补齐） | 60 | pc=60 + fields×1 + pl |
| 130 | `ftp_dyn_payload_list` | 正 | 会话 payload_dyn list（数据通道载荷策略补齐） | 60 | pc=60 + fields×1 + pl |
| 131 | `ftp_dyn_payload_fixed` | 正 | 会话 payload_dyn fixed（数据通道载荷策略补齐） | 60 | pc=60 + fields×1 + pl |
| 132 | `ftp_ipv6_dyn_src_inc` | 正 | IPv6 动态 ip.src inc：3 流 2001:db8::1→::3（T-FTP-18，对称 dyn-ip 格） | 21（实测） | pc=21 + fields×1 + pl + distinct×1 |
| 133 | `ftp_ipv6_dyn_src_rand` | 正 | IPv6 动态 ip.src rand seed=7（T-FTP-18，可复现格） | 21（实测） | pc=21 + fields×1 + pl + distinct×1 |
| 134 | `ftp_ipv6_dyn_src_list` | 正 | IPv6 动态 ip.src list 轮转（T-FTP-18） | 21（实测） | pc=21 + fields×1 + pl + distinct×1 |
| 135 | `ftp_ipv6_dyn_dst_fixed` | 正 | IPv6 动态 ip.dst fixed 常量 + 端口 inc 防撞（T-FTP-18） | 21（实测） | pc=21 + fields×1 + pl + distinct×1 |
| 136 | `ftp_epsv_passive_download` | 正 | RFC 2428 §3 EPSV 被动下载：EPSV→229(\|\|\|50010\|)→RETR→数据→226（T-FTP-19） | 25（实测） | pc=25 + fields×1 + hs + pl |
| 137 | `ftp_eprt_active_upload` | 正 | RFC 2428 §4 EPRT 主动上传：EPRT\|2\|…\|50011\|→STOR→数据(server首SYN)→226（T-FTP-20） | 25（实测） | pc=25 + fields×1 + hs + pl |
| 138 | `ftp_epsv_500_fallback` | 正 | RFC 2428 §5 EPSV→500 不支持扩展模式：无数据通道（T-FTP-21） | 14（实测） | pc=14 + fields×2 |
| 139 | `ftp_eprt_522_reject` | 正 | RFC 2428 §5 EPRT→522 网络协议不支持：无数据通道（T-FTP-21） | 16（实测） | pc=14 + fields×2 |
| 140 | `ftp_ipv6_sessions_mixed` | 正 | 对称：IPv6 双会话（EPSV 被动下载 + EPRT 主动上传，对标 mixed_mode）（T-FTP-21） | 46（实测） | pc=40 + fields×1 + pl + distinct×1 |
| 141 | `ftp_ipv6_multiflow` | 正 | 对称：IPv6 多流×会话×数据通道（flows=2，会话端口动态，对标 multiflow_multisession）（T-FTP-21） | 44（实测） | pc=40 + pl |

> **读表纪律**：第 4 列是 `summary` **原文照抄**（含 4 处与实测不符的旧帧数，见 §8.2 第 5 条）；**包数列才是权威**。**第 2 列 ID 顺序 = `cases/ftp.json` 数组顺序**（即未来 JSON 顺序，保持稳定）。

## 3. 正例逐项断言契约（最低断言集，实现期可增不可减）

136 正例**全部**含 `min_packets` + `negotiated` + `terminates`；104 例含 `packet_count`（= `min_packets`）；122 例含字段级断言。本节给**代表性分组**的逐项断言（完整 141 行见 §2）。

### 3.1 冒烟基线（`ftp_smoke_01`，14 帧，唯一有 frame hex 断言的用例）

`layers = [ip{10.0.0.1→20.0.0.1}, tcp{12345→21}, ftp{banner:"220 FTP server ready", commands:[USER/PASS/QUIT]}]`。

- `packet_count=14`、`min_packets=14`、`has_handshake=true`、`terminates=true`、`negotiated=true`。
- 字段：pkt1 `tcp.dstport=21`；pkt4 `ftp.response.code=220` + `ftp.response.arg=FTP server ready`；pkt5 `ftp.request.command=USER` + `ftp.request.arg=anonymous`；pkt6 `ftp.response.code=331`；pkt7 `ftp.request.command=PASS`；pkt8 `ftp.response.code=230`；pkt9 `ftp.request.command=QUIT`；pkt10 `ftp.response.code=221` + `ftp.response.arg=Goodbye`。
- frames（offset 54）：pkt4 `32 32 30 20`（`"220 "`）；pkt5 `55 53 45 52 20 61 6e 6f 6e 79 6d 6f 75 73 0d 0a`（`"USER anonymous\r\n"`）；pkt10 `32 32 31 20 47 6f 6f 64 62 79 65 0d 0a`（`"221 Goodbye\r\n"`）。
- **帧位证据**：3 握手（1–3）+ banner（4）+ 3 命令×2（5–10）+ 4 挥手（11–14）= 14 ✓（`min_packets` 公式：`3 + 1 + 2×3 + 4`）。

### 3.2 流关联（数据通道）：`ftp_retr_passive`（27 帧）与 `ftp_stor_upload`（27 帧）

`ftp_retr_passive`：PASV 应答 `227 Entering Passive Mode (20,0,0,1,195,73)` → **195*256+73 = 49993**；`RETR /data.bin` 带 `emit_data_channel=true`。

- 字段：pkt1 `tcp.dstport=21`；pkt10 `ftp.response.code=227`；pkt11 `ftp.request.command=RETR` + `ftp.request.arg=/data.bin`；pkt12 `ftp.response.code=150`；**pkt13 `tcp.dstport=49993`**（数据连接 server 口 = 信令通告口，**流关联主证据**）；pkt21 `ftp.response.code=226`；pkt22 `QUIT`；pkt23 `221`。
- 实测帧位：12=150 → **13–19 数据连接**（3 握手 + 1 PSH + 3 挥手；帧 16 `tcp.len=14`）→ 20=226。**数据帧插在 150 与 226 之间**（老形状插入位置，设计 §6.3）。
- 数据连接客户端口 = 控制口 + 1 = **12346**（实测帧 13 `12346→49993`）。

`ftp_stor_upload`：PORT 命令 → active 模式。

- 字段：pkt9 `ftp.request.command=PORT`；pkt10 `ftp.response.code=200`；pkt11 `ftp.request.command=STOR`；**pkt13 `tcp.srcport=20`**（active 数据连接 server 口 = 20，**server 首 SYN**）；pkt21 `ftp.response.code=226`。
- 实测帧位：帧 13 `20→12371` SYN（**服务端发起**）→ 帧 16 `20→12371` PSH `tcp.len=14`。

### 3.3 事务域隔离：`ftp_txindex_dual`（32 帧）/ `ftp_pasv_isolation`（32 帧）

- `ftp_txindex_dual`：pkt1 `tcp.srcport=22000`；**pkt9 `tcp.dstport=50011`**；**pkt21 `tcp.dstport=50012`** —— 两数据流各取**本事务**的 PASV 端口（`195,91`=50011 / `195,92`=50012）。
- `ftp_pasv_isolation`：pkt1 `tcp.srcport=21000`；**pkt9 `tcp.dstport=49993`**；**pkt21 `tcp.dstport=49994`** —— 后事务**不串**前事务的 49993。

### 3.4 空会话与不发射：`ftp_empty_session`（7 帧）/ `ftp_noflag_no_subflow`（9 帧）

- `ftp_empty_session`：`sessions:[{src_port:23001}]`（**零事务**）→ pkt1 `tcp.srcport=23001` + `tcp.dstport=21`；**7 帧 = 3 握手 + 4 挥手**（无载荷纯控制事件，设计 §5.3 自动派生表）。
- `ftp_noflag_no_subflow`：事务有 `data_channel` 但命令**无** `emit_data_channel` → pkt4 `ftp.request.command=RETR`；pkt5 `ftp.response.code=150`；**9 帧**（无数据子流）。

### 3.5 多会话：`ftp_sessions_dual`（46 帧）/ `ftp_3sessions_mixed`（61 帧）/ `ftp_multiflow_multisession`（70 帧）

- `ftp_sessions_dual`：pkt1 `tcp.srcport=20000`；pkt24 `tcp.srcport=20001` —— 两会话独立控制连接，各带数据通道（15 + 8）×2 = 46。
- `ftp_3sessions_mixed`：会话1 空（11 帧）+ 会话2 RETR（17 + 8）+ 会话3 LIST（17 + 8）= 61；`distinct_values` 断言 `tcp.srcport` 含 26000/26010/26020。
- `ftp_multiflow_multisession`：**flows=2 × 每流 2 会话**，但会话 `src_port_dyn inc [41000,41001]` **按流序号解析** → 同流两会话**同值** → **每流仅 2 条 TCP 连接**（41000、41001），70 帧 = 2×35。`distinct_values` = `["41000","41001"]`，`distinct_exclude` = `["21","41002","50000","50100"]`。**用例 `notes` 已自陈此行为**（设计 §5.2/G-FTP-3）。

### 3.6 端口推导边界：`ftp_dataconn_fallback`（25）/ `ftp_dataconn_explicit_ports`（27）/ `ftp_port_overflow`（25）

- `ftp_dataconn_fallback`：无 PASV/PORT 信令 → **pkt11 `tcp.dstport=50000`**（回退值）。
- `ftp_dataconn_explicit_ports`：显式 `src_port`/`dst_port` **覆盖** PASV 信令（最高优先级）。
- `ftp_port_overflow`：`tcp.src_port=65535` → 数据客户端口回退 **1024**（实测帧 11 `1024→50000`，**不回绕 0**）。

### 3.7 RFC 2428 扩展：`ftp_epsv_passive_download`（25）/ `ftp_eprt_active_upload`（25）/ 两条拒绝例

- `ftp_epsv_passive_download`：EPSV → 229 `(\|\|\|50010\|)` → RETR；实测帧 15 `38101→50010`（客户端口 = 38100+1）。
- `ftp_eprt_active_upload`：EPRT `\|2\|…\|50011\|` → STOR；**server 首 SYN**。
- `ftp_epsv_500_fallback`（14 帧）/ `ftp_eprt_522_reject`（16 帧）：**应答码层面的拒绝** → **无数据通道发射**（不是配置拒绝，是正例）。

### 3.8 动态字段（35 例，全部 `sessions[]` 形状）

五策略 × 五站点（`ip.src`/`ip.dst`/`tcp.src_port`/`tcp.dst_port`/会话 `src_port`/`banner`/`cmd`/`response`/`payload`）实测分布：`inc` 37 / `rand` 10 / `list` 8 / `fixed` 11 / `pattern` 5（`strategy` 出现次数，含嵌套）。

- **回绕**：`ftp_dyn_sessport_wraparound`（`range[33300,33301]` + `flows=4` → 33300/33301/33300/33301，36 帧）。
- **可复现**：`*_rand` 系列全部 `seed=7`，同 seed 同值。
- **list 轮转**：`ftp_dyn_sessport_list` 3 流取 33101/33102/33103。
- **fixed 动态对象豁免静态复制**：`ftp_dyn_sessport_fixed`（常量 33200 + `flows=3`，**不触发** `validateSessionStaticCopy`）。
- **IPv6 对称格**：`ftp_ipv6_dyn_src_inc`/`_rand`/`_list`/`ftp_ipv6_dyn_dst_fixed`（2001:db8::1→::3）。

### 3.9 性能：`ftp_perf_100flows`（1400）/ `ftp_perf_1000flows`（14000）

100/1000 流 × `USER/PASS/QUIT`（banner 1 + 3×2 = 7 帧/流）× 单连接（3+7+4 = 14）= 1400 / 14000 ✓。`distinct_values` 断言 `tcp.srcport` 逐流不同（保底自增 `12345+i`）。

## 4. 负例契约

**5 条负例，全部配置/校验类**；锚词与代码字面值逐条对照（机读实测 `cases/ftp.json`）：

| ID | 故障输入 | JSON `error_contains` | 代码锚词（逐字） | 代码位置 | 失败点 |
|---|---|---|---|---|---|
| `ftp_neg_static_copy` | 层链显式标量四元组 + `flows=2` | `static four-tuple` | `layers pin a static four-tuple but flows > 1: …` | `schema/semantic.go:285` | **创建期 400**（schema 层） |
| `ftp_neg_mss_too_small` | `tcp.mss=100` | `out of range` | `layers: layer %q field %q = %v invalid: out of range [536,65535]` | `layers/complete.go:325`（范围 `registry.go:68`） | **创建期**（V9 层校验） |
| `ftp_neg_dyn_no_range` | `sessions[0].src_port={"strategy":"inc"}` 无 range + `flows=2` | `range` | `ftp sessions[0].src_port: inc strategy requires a 2-element range` | `ftp.go:165` | **任务启动期**（ftp `Validate`） |
| `ftp_neg_session_static_copy` | 2 会话固定 `src_port` + `flows=2` | `static copy` | `ftp: flows=2 with pinned session src_port emits 2 identical control connections (static copy). …` | `ftp.go:121` | **任务启动期**（ftp `Validate`） |
| `ftp_dyn_neg_port_pattern` | `tcp.src_port={"strategy":"pattern",…}` | **（空串）** | `layers[1](tcp).src_port: pattern strategy is not supported for layer address/port fields` | `layer_dyn.go:508` | **创建期**（`validate_layers.go:1004` 面） |

**锚词口径**：`error_contains` 是**子串**判定；`layer_chain_suite_test.go:329` 的 `if want := …; want != "" && !strings.Contains(errText, want)` 表明**空串 = 只断言"任务失败"，不断言锚词**。故 `ftp_dyn_neg_port_pattern` 是**唯一一条锚词未钉的负例**（G-FTP-9）。

**负例原子性**：每例单一故障注入；单次执行不得混注（实测：5 例各自只注入一处）。

**失败点归属（重要，不得笼统称"ftp 校验拒绝"）**：`ftp_neg_static_copy`/`ftp_neg_mss_too_small`/`ftp_dyn_neg_port_pattern` 三条**在创建期**（schema/V9 层校验，**不经 ftp planner**）；`ftp_neg_dyn_no_range`/`ftp_neg_session_static_copy` 两条**在任务启动期**（ftp planner `Validate`）。用例 `notes` 已逐条注明。

**expect 键形状注**：5 条负例 `expect` = `{expect_error, error_contains, notes}`（**含 `notes`**），与严格两键口径（`{expect_error, error_contains}`）**不符** → G-FTP-9（P4 收窄时删 `notes`）。

**负例纯净性**：5 条负例均**只有** `expect_error`/`error_contains`/`notes` 三键，**零成功包结构断言** ✓。实测 2 条有 `.neg.pcap`（`ftp_neg_dyn_no_range`/`ftp_neg_session_static_copy`），3 条无（G-FTP-1）。

**未入用例的拒绝分支（A′ 立项，不得冒充已覆盖）**：`invalid source IP`（`ftp.go:70`）/ `invalid destination IP`（`:75`）/ `MSS %d too small (min %d per RFC 879)`（`:81`，**planner 侧**，与 `ftp_neg_mss_too_small` 的 V9 侧**不是同一分支**）/ `ftp %s: list strategy requires a non-empty list`（`:173`）/ `ftp %s: pattern strategy requires a template and a 2-element range`（`:178`）/ `ftp %s: pattern range start must not exceed end`（`:181`）/ `ftp %s: unknown dynamic strategy %q`（`:185`）/ `ftp %s: %s range start must not exceed end`（`:168`）/ `does not support dynamic`（`validate_layers.go:1004`）/ `unknown field`（V9）。→ G-FTP-6。

**未入用例的静默路径（缺陷候选）**：`file_source` 形状不匹配 → 数据通道**静默不发**（G-FTP-2）；`PayloadCache` 未注入 → 同上；`data_channel.mss` 忽略（G-FTP-4）；`dc.Direction` 忽略（G-FTP-5）；`username`/`password`/顶层 `transactions` 三 registry 键无消费者（G-FTP-10）；老形状动态字段被解析但不生效（G-FTP-12）。

**不得误报的合法协议事件**：空会话 7 帧（`ftp_empty_session`）；空命令跳过（`ftp_retr_passive` 的 226 轮次）；无 emit 标记不发射（`ftp_noflag_no_subflow`）；`direction` 被忽略（G-FTP-5）；`abort_after_bytes >= len`（no-op）；RFC 2428 的 500/522 拒绝（**正例**，不是负例）。

## 5. 覆盖与对账

### 5.1 三源回指行

RFC 959 §3/§4/§5 + RFC 2428 §3/§4/§5 + RFC 879（设计 §10）+ D-FTP-1（设计 §11）+ tshark 3.6.14 字段表与 **138 例实测 pcap**（`/tmp/mcp-pcaps/ftp/`）→ 141 ID（本契约 §2）。**第三源"已确认现网行为"当前 = 抓包级已到，但抓的是本仓引擎自产 pcap（自证）**，**真实服务器/客户端线字节未取到** → G-FTP-11（按设计 §5.5 不写死进实现）。

**141 ID 逐项回指（抽样，全量见 §2 第 4 列 summary 的 RFC 章节号）**：`ftp_smoke_01`←RFC 959 §4.1；`ftp_retr_passive`←§4.1.2+§3.2（设计 §3.4/§6.1）；`ftp_stor_upload`←§4.1.2+§3.3；`ftp_txindex_dual`/`ftp_pasv_isolation`←设计 §6.2；`ftp_empty_session`←设计 §5.3；`ftp_noflag_no_subflow`←设计 §5.2；`ftp_dyn_*`←设计 §12.12；`ftp_epsv_*`/`ftp_eprt_*`←RFC 2428 §3/§4/§5；负例 5 条←设计 §7。

### 5.2 对账两行 + 清单出处声明

- **清单出处声明**：本清单来源 = **RFC 959/RFC 2428/RFC 879 公开语义 + tshark 3.6.14 字段表 + 本仓引擎自产 138 例 pcap + 落码反推**，**非纯规范反推**（真实服务器线字节未取 → G-FTP-11）。
- **对账两行**：**要求逻辑点总数 = 68**（八项 8 行 + 命令×终态矩阵 12 格 + 数据形态变体 26 行 + 商业映射 15 行 + 负例锚词 5 条 + 流关联面 2 条）；**用例覆盖数 = 141**（141 ID 逐一对应上表逻辑点，其中多条 ID 覆盖同一逻辑点属正常形态，§7 明确不做一对一映射）；**不适用 = 4**（八项 1 + 矩阵 1 + 商业 3 → 减去重叠）；**开放立项 = 15**（G-FTP-1…G-FTP-15）。
  **粒度声明**：行/格粒度每点 1 计；G-FTP-1…G-FTP-15 不折进 68。**反查全绿 ≠ 覆盖全**。逐表重数见设计 §10.1（八项 8 = 覆 5 + 立项 2 + 不适用 1）/§10.2（12 格 = 覆 9 + A′ 2 + 不适用 1）/§10.3（26 行 = 覆 24 + A′ 2）/§10.4（15 行 = 覆 12 + 不解决 3）。
- **门3 抽查候选**：最复杂用例 = **`ftp_multiflow_multisession`**（70 帧：flows=2 × 每流 2 会话 × 各挂数据通道；交织维度 = 流(2) × 会话(2) × 连接(2/流) × 数据通道(2/流) × 端口解析域(流序号)）；**建议门3 抽 `ftp_multiflow_multisession` + `ftp_retr_passive`**（后者补流关联插入位置面）。

### 5.3 T-FTP 编号对照（设计 §0.1 全表摘要）

机读实测：15 个 `T-FTP-*` 编号在案（其余用例无编号）。对照：

| T-编号 | 用例 | T-编号 | 用例 |
|---|---|---|---|
| T-FTP-2 | `ftp_retr_passive` | T-FTP-11 | `ftp_dyn_command_pattern` |
| T-FTP-2b | `ftp_stor_upload` | T-FTP-11b | `ftp_response_dyn` |
| T-FTP-2 sessions | `ftp_sessions_dual` | T-FTP-12 | `ftp_dyn_payload` |
| T-FTP-3 | `ftp_txindex_dual` | T-FTP-18 | `ftp_ipv6_dyn_src_inc`/`_rand`/`_list`/`ftp_ipv6_dyn_dst_fixed` |
| T-FTP-4 | `ftp_pasv_isolation` | T-FTP-19 | `ftp_epsv_passive_download` |
| T-FTP-5 | `ftp_empty_session` | T-FTP-20 | `ftp_eprt_active_upload` |
| T-FTP-6 | `ftp_noflag_no_subflow` | T-FTP-21 | `ftp_epsv_500_fallback`/`ftp_eprt_522_reject`/`ftp_ipv6_sessions_mixed`/`ftp_ipv6_multiflow` |
| T-FTP-10 | `ftp_session_dynamic_ports` | — | — |
| T-FTP-10b | `ftp_banner_dyn_list` | — | — |

**T-FTP-1/7/8/9/13–17 无对应用例**（机读零命中）——**旧编号体系不完整**，本版 §2 以 **141 个 JSON ID 为唯一权威**，T-编号仅作历史对照（G-FTP-13）。

## 6. P3 固定动作（CORE_MEMORY 管线：§3.15 三项 + A′/B′ 两分类 + 3.14 豁免）

### 6.1 §3.15 三项逐项一例或立项

| # | 三项 | 本协议对照 | 用例/立项 |
|---|---|---|---|
| ① | 同连接/同流内的多轮操作 | 单控制连接内多事务（`ftp_txindex_dual` 2 事务、`ftp_pasv_isolation` 2 事务、`ftp_session_partial_data_tx` 3 事务）；同连接内多命令（`ftp_multi_command` 6 命令、`ftp_file_mgmt` 4 连） | 已覆（4 例） |
| ② | 非正常结束 | **正常 FIN 全正例**（136/136 `terminates=true`）；**应用层异常** = ABOR 三情形（`ftp_abor_completed`/`_midtransfer`/`_idle`）+ 失败应答（15 例 4xx/5xx）；**传输层异常 = RST**（框架 tcp 层能力，**本层零断言**） | 已覆（ABOR 3 + fail 15）；**RST A′ 立项**（G-FTP-6） |
| ③ | 长保活 | **协议层无保活定时器**；`NOOP` 是普通命令（`ftp_min_noop`）；`REIN` 是重初始化（`ftp_login_rein`）；`421` 是服务端超时（`ftp_service_421`） | 已覆（3 例）；**无真实保活 = 显式不适用**（生成器无定时器语义） |

无空项：① 4 例；② 已覆 + 1 条 A′；③ 已覆 + 显式不适用声明。

### 6.2 A′/B′ 两分类表

**A′（P4 接线）**：

| 类 | 内容 | 落点 |
|---|---|---|
| `file_source` 形状面 | `ftp_file_source`/`ftp_file_source_abort` 载荷未上路（改 cases 形状或扩 `parseFileSource`） | G-FTP-2 |
| 会话索引域面 | 会话级 dyn 按流序号解析（维持 + 文档化，或引入会话序号域） | G-FTP-3 |
| 通道级 MSS 面 | `data_channel.mss` 链路径忽略（补实现或删字段） | G-FTP-4 |
| 载荷方向面 | `dc.Direction` 链路径忽略（接线或删字段 + 用例文案同步） | G-FTP-5 |
| 线格式负例面 | 畸形 227 六元组 / 畸形 EPRT / 端口越界 / 多行 227 续行 / `227\t` 劫持（**只能写"推导回落"正例**，不能写 `expect_error`） | G-FTP-6 |
| 失败应答面 | 22 条命令无 4xx/5xx 例（按 RFC 959 §4.2.1 逐命令补） | G-FTP-15 |
| 拒绝分支面 | `invalid source/destination IP` / planner 侧 MSS 下限 / dyn list 空 / dyn pattern 无 range / dyn unknown strategy / `does not support dynamic` | G-FTP-6 |
| RST 面 | `tcp.rst` 补例 | G-FTP-6 |
| FTPS 面 | `OptionalOn ["tls"]` 已声明但零用例 | G-FTP-7 |
| field 断言面 | 收编 tshark `ftp.*` 29 个未用字段（尤其 `ftp.setup-frame`/`ftp.command-response.frames` = **流关联官方断言通道**） | G-FTP-8 |
| 负例形状面 | 删 `notes`（5 条）+ 补 `ftp_dyn_neg_port_pattern` 锚词 + 补顶层 `ftp` presence 负例 | G-FTP-9 |
| registry 死键面 | `username`/`password`/`transactions` 三键无消费者 | G-FTP-10 |
| 老形状动态面 | `emitLegacy` 不调 `resolveTx` → 老形状 dyn 静默无效 | G-FTP-12 |
| 编号面 | T-FTP-1/7/8/9/13–17 无对应用例 | G-FTP-13 |

**B′（框架面）**：游离顶层未知键通用门（`unknown field`）——G-FTP-9，**等框架级 unknown-key 白名单，不单独立项，禁加单协议黑名单分支**。进设计 §14，「明确不解决 + 迁入计划」。

### 6.3 3.14 豁免边界审计

**有长连接载体（TCP）→ `sessions[]` 不豁免**（设计 §12.3 会话表）；`sessions` 是**层内结构选择器**（本协议 `sessions[]` 是**真正的多连接数组**，与 opcua 的"sessions 连续 N 对 Read"形态不同——**本协议 sessions 就是会话**，无形态差异需声明）；多流并发由策略级 `flow_control {"flows": N}` 承载（51 例实测）；**流关联（控制流派生数据流）本协议是核心维度**（48 例含数据通道、55 条数据通道实例，设计 §6 专章）；**单包多载荷** = **不适用**（FTP 每帧一个命令或一个应答，无多 question/多 RR 类形态，如实声明）。

## 7. 实现后执行建议

1. **P4 顺序**：①先修 G-FTP-2（`file_source` 形状——改 cases 或扩 `parseFileSource`）与 G-FTP-5（`direction` 接线或删字段 + 用例文案同步），两者影响**载荷是否上路**与**方向语义**；②G-FTP-4（`data_channel.mss`）与 G-FTP-12（老形状 dyn）裁定；③收编 `ftp.*` field 断言（G-FTP-8）；④补负例（G-FTP-6/G-FTP-9）；⑤全量复跑。**本协议无 §1 迁移步骤**（顶层零残留）。
2. **实测顺序**：先 `ftp_smoke_01`（14 帧基线 + frame hex），再 `ftp_retr_passive`（PASV 49993 + 插入位置），再 `ftp_empty_session`（7 帧空会话），再 `ftp_txindex_dual`/`ftp_pasv_isolation`（事务域隔离），再 `ftp_epsv_passive_download`（RFC 2428），最后 `ftp_multiflow_multisession`（多流多会话 + 会话合并边界）。
3. **二进制与 HEAD 同代确认**（门2③：`find trafficgen -name '*.go' -newer <server-binary>` 无输出）；门2② 全量（`CHAIN_PROTO=ftp` 全量不是增量）；门2④ 反查绿后进 P6。
4. **本协议不需要外部依赖**（无 `file_source` 真实文件读取要求——若 P4 决定补 PayloadCache 注入，须同时评估离线套件）。

## 8. 存量审计（141 例逐条去向）

### 8.1 存量实测面（2026-09-29）

`cases/ftp.json` **141 例**：136 正 + 5 负；**141/141 顶层键仅 `{layers}`（+51 例 `strategy_fc`），零残留**；包数三方对账 **138/138 一致**（§1）；`packet_count == min_packets` **104/104**；331 条 `fields` 断言 + 3 条 `frames` 断言 + 58 条 `distinct_values` 断言；**138 例真实 pcap 在案**（`/tmp/mcp-pcaps/ftp/`，2026-09-27），3 条负例无 pcap。

**分组统计（互斥，合计 141）**：冒烟/多命令 2 / 会话·多流 10 / RFC 959 命令枚举 23 / 应答码分支 49 / 动态字段 38 / IPv6 12 / 性能 2 / 负例 5。**含数据通道发射的用例 48**（非互斥，跨组）；数据通道实例 **55 条**（`mode×direction` = passive/down 42 + active/up 7 + passive/up 5 + active/down 1）；载荷来源 = 内联 `payload` 52 + `payload_b64` 1 + `file_source` 2；带 `abort_after_bytes` 4；带 `mss` 1；带显式端口 1。

### 8.2 现状矛盾点（P4 前诚实登记）

1. **`file_source` 载荷静默不发（G-FTP-2，confirmed）**：2 例（`ftp_file_source`/`ftp_file_source_abort`）的 `file_source` 写 `{"source_type":"literal","content":…}`，`parseFileSource` 只认 `literal`/`file`/`fill`/`random` → 解析 nil → 数据连接**只有 7 帧、无 PSH**。**证据**：`tshark -r ftp_file_source.pcap` 帧 13–19 `tcp.len` 全 0。**根因链完整见设计 §11.5。**
2. **`direction` 声明与实测相反（G-FTP-5，confirmed）**：**55 条数据通道实例中 42 条声明 passive/down 而实测载荷为 up（client→server）**；7 条声明 active/up 而实测 down（server→client）；仅 5 条 passive/up + 1 条 active/down 与实测巧合一致。**证据**：`ftp_retr_passive.pcap` 帧 16 `12346→49993`（client 发）；`ftp_stor_upload.pcap` 帧 16 `20→12371`（server 发）。**`dc.Direction` 在链路径被显式丢弃**（`layer_gen.go:273`）。**注意**：用例**不断言载荷方向**（只断端口与帧位），故包数与断言**不受影响**——这是"语义存疑"不是"用例失守"。
3. **`data_channel.mss` 被忽略（G-FTP-4）**：`ftp_dc_mss_override`（`mss=536`、2200B）实测按 1460 分 2 段（应 536×5 段）；`grep -n 'dc.MSS' layer_gen.go` 零命中。用例 `notes` 已自陈"B 类缺口登记"。
4. **会话级 dyn 按流序号解析（G-FTP-3）**：`ftp_multiflow_multisession` 同流两会话解析同值 → 每流仅 2 条连接（70 帧而非 84）。用例 `notes` 已自陈。**非缺陷，已声明边界。**
5. **4 处 `summary` 帧数与实测不符（G-FTP-14）**：`ftp_retr_passive`（说 28，实测 27）、`ftp_stor_upload`（说 28，实测 27）、`ftp_dyn_command_pattern`（说 46，实测 44）、`ftp_dyn_payload`（说 46，实测 44）——`summary` 是**文案字段**（非断言），但**包数描述与实测不符**应改写（P4 动作）。`ftp_retr_passive` 的 notes 更详细自陈了正确拆解（"控制 18 + 数据 9 = 27"），仅 summary 未同步。
6. **3 条负例无 pcap（G-FTP-1）**：`ftp_neg_static_copy`/`ftp_neg_mss_too_small`/`ftp_dyn_neg_port_pattern` 在 `/tmp/mcp-pcaps/ftp/` 无 `.neg.pcap`（138/141）。
7. **结果产物：数字未经今日复跑 + pcap 留档缺失（G-FTP-1）**：`trafficgen/docs/protocol-pcap-test/ftp.md` 标 141/141 pass，但 ① **数字未经本车道今日复跑证实**（本车道未跑套件，产物未标跑测日期）；② `docs/protocol-pcap-test/ftp/` 目录**不存在**，141 条 pcap 链接**全悬空**；③ 3 条负例无 `.neg.pcap`。**澄清**：末次提交 `711423d`（2026-09-19）**晚于**判死提交 `0417be5`，且该提交是对产物的**修正**（`01fab60` 只 139 行 → 补 2 行 + 修 `ftp_neg_static_copy` 包数 18→0）——**不是“过期/错位产物”**；**行内包数与真实 pcap 138/138 一致**。故本项**不是“不可跑”也不是“包数错”**。**归属代码阶段**（P5 重跑后重生成）。
8. **registry 3 键无消费者（G-FTP-10）**：`username`/`password`（`FTPConfig` 无对应字段）+ 顶层 `transactions`（`ParseFTPConfigFromMap` 不读）。
9. **老形状动态字段静默无效（G-FTP-12）**：`emitLegacy` 不调 `resolveTx`；存量 35 例动态用例**全部用 `sessions[]` 形状**，故未暴露。
10. **tshark `ftp.*` 29 字段零使用（G-FTP-8）**：尤其 `ftp.setup-frame`（流关联官方断言通道）。
11. **存量未覆盖**：`response==""` 分支、`abort_after_bytes >= len`、`invalid source/destination IP`、planner 侧 MSS 下限、dyn list 空、dyn pattern 无 range、dyn unknown strategy、`does not support dynamic`、顶层 `ftp` presence、FTPS/TLS、RST、线格式负例（畸形 227/EPRT/端口越界）——**今日零用例**（A′ 补）。
12. **T-编号体系不完整（G-FTP-13）**：15 个编号在案，T-FTP-1/7/8/9/13–17 无对应用例（机读零命中）。

### 8.3 逐条去向表（141 行）

**去向判定规则**：① `packet_count`/`min_packets`/ID/顺序与 cases JSON 一致 → **保留**；② 涉及 G-FTP-2/4/5/12/14 的用例 → **改写**（P4 修代码或改文案后重钉）；③ 无作废。

| 分组 | 例数 | 去向 | 改写动作（P4） |
|---|---:|---|---|
| 冒烟/多命令（2） | 2 | **保留** | 可补 `ftp.setup-frame` 断言（G-FTP-8） |
| 会话/多流（10） | 10 | **保留**（`ftp_multiflow_multisession` 文案已自陈，无需改） | 补会话索引域说明（G-FTP-3） |
| RFC 959 命令枚举（23） | 23 | **保留** | 可补 `ftp.request.command` 全枚举断言 |
| 应答码分支（49） | 49 | **保留** | 补 4xx/5xx 全枚举断言 |
| 动态字段（38） | 38 | **保留** | 老形状 dyn 若接线须补老形状例（G-FTP-12） |
| IPv6（12） | 12 | **保留** | 可补 `ipv6.*` 断言 |
| 性能（2） | 2 | **保留** | 无 |
| 流关联（跨组 48 例含数据通道） | 48 | **改写**（`ftp_file_source`/`ftp_file_source_abort` 修形状或改代码；`ftp_retr_passive`/`ftp_stor_upload` 改 summary 帧数） | G-FTP-2/G-FTP-14 |
| 负例（5） | 5 | **改写**（删 `notes`、补锚词、补 pcap） | G-FTP-9/G-FTP-1 |

**无"作废不注原因"**：0 作废，0 等价覆盖（141 例全部保留/改写 + A′ 新增）。**本协议存量 141/141 顶层零残留**（与 opcua/bacnet/edce 等共 27 个协议同为纯层链形，**非全仓唯一**；见设计 §12.1 注）。

## 9. 附：覆盖反查门建议断言行（供主线程合后登记；本车道不碰 `coverage_gate.py`）

建议在主线程合入后，于 `coverage_gate.py` 的 ftp 段登记下列断言（**每条均可从本契约与 cases JSON 直接机读，不需新造事实**）：

| # | 建议断言 | 依据 |
|---:|---|---|
| 1 | `len(cases['ftp']) == 141` 且 ID 集合 = §2 一百四十一项，顺序一致 | 本契约 §2 |
| 2 | 141/141 例 `spec_json` 顶层键 ⊆ `{layers}`（**本协议零游离键**） | 本契约 §1；设计 §12.1 |
| 3 | 非负例顶层键计数 == 0（**今日已成立**） | 设计 §12.1 |
| 4 | 负例数 == 5，且 ID 集合 = §4 五项 | 本契约 §4 |
| 5 | 负例 `error_contains` ∈ 代码锚词集 `{"static four-tuple", "out of range", "range", "static copy"}`（`ftp_dyn_neg_port_pattern` 空串除外，P4 补齐后加入 `pattern strategy is not supported`） | 设计 §7 |
| 6 | 有 `packet_count` 的正例数 == 104，且 `packet_count == min_packets`（104/104） | 本契约 §1 |
| 7 | 每正例至少一条 `min_packets` + `negotiated` + `terminates` | 本契约 §1 |
| 8 | 层形 ∈ `{[ip,tcp,ftp], [tcp,ftp]}`（110/31） | 本契约 §1 |
| 9 | IPv6 例数 == 12 | 本契约 §1 |
| 10 | `strategy_fc.type` ∈ `{"flows"}`（51 例） | 本契约 §1 |
| 11 | 负例 `expect` 键 == `{expect_error, error_contains}`（P4 删 `notes` 后） | 本契约 §4 |
| 12 | 无 pcap 的用例 == 3（3 条负例）→ P5 补 pcap 后应为 0 | 设计 §0.3/G-FTP-1 |

**另注意**：`docs/protocol-pcap-test/ftp.md` 的 141/141 pass 是**未经今日复跑证实**的数字（G-FTP-1：本车道未跑套件；`docs/protocol-pcap-test/ftp/` 目录不存在致 141 条链接全悬空；3 条负例无 pcap），**不得作为“今日已复跑”依据**（口径与 pcep G-PCEP-11 / opcua G-OPCUA-10 一致）。**但 ftp 的 141 例今日应可跑**（141/141 顶层键仅 `{layers}`，机读实测），且**包数经 138 例真实 pcap 逐条复核全对**——该提醒**仅限**“数字未经今日复跑 + 链接悬空 + 3 负例无 pcap”，**不得读成“套件不可跑”或“包数错”**（另：该产物**不是**过期产物——末次提交 `711423d` 2026-09-19 **晚于**判死提交 `0417be5`，且是对产物的修正）。

## 10. 修订记录

- v1.0.0（2026-09-29）：P-PIPE 文档轨批次二 · as-built 契约首版（ftp 首份用例文档）。§1 形状基线机读实测（**141/141 顶层零残留**；**包数三方对账 138/138 一致**）；§2 一百四十一行逐 ID 索引（ID/场景/包数/断言，与 cases JSON 逐条一致）；§3 九个代表性分组的逐项断言（含 `ftp_smoke_01` 3 条 frame hex）；§4 负例契约（5 条 + 锚词逐字 + **失败点归属三条创建期/两条启动期**）；§5 三源回指 + 对账两行 + T-编号对照（**15 个编号在案，其余无对应**）；§6 P3 固定动作（§3.15 三项 + A′/B′ + 3.14 豁免）；§7 执行建议；§8 存量审计（12 条矛盾点 + 逐组去向）；§9 覆盖反查门建议断言行 12 条。
  **自审 3 轮，末轮干净**（机读脚本复核）。第 1 轮：141 行索引 ID 顺序 = JSON 顺序、类型列 = `expect_error`、104 条 `packet_count` 逐行一致，全部通过。第 2 轮修复：G-FTP-13/G-FTP-14 引用与设计缺口表对齐、`G-FTP-1…G-FTP-15` 范围同步、§8.2 第 7 条改写（原"过期/错位"表述经 `git show` 实测证伪）。第 3 轮修复：A′ 表补"失败应答面"（G-FTP-15）。**第 3 轮全部机读断言 0 失败**。

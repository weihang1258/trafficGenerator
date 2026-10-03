# #115 telnet（TELNET）测试用例契约

> 版本：v1.1.0（批次二文档车道 P4 修订，as-built 型）
> 日期：2026-09-29
> 配套设计：`docs/protocols/telnet/design.md` v1.0.0（D-TELNET-1 as-built 定稿）
> 旧基线：**存在旧编号用例文档**（`docs/protocol-designs/115-telnet-testcase.md`）；本版为其迁入 `docs/protocols/telnet/` 的 P4 修订。权威来源 = ①`docs/TEST_CASES.md` §T-TELNET-1…17（**已验收**）；②存量 1 例扁平用例（`git show d58bef9~1:…cases/telnet.json`）；③`docs/CODE_DESIGN.md` §D-TELNET-1（**已验收**）
> 机器契约：`trafficgen/test/protocol_pcap/cases/telnet.json`（**17/17 ID 与本版 §2 一致，顺序一致，已机读实测**；合法正例 `spec_json` 顶层键均为 `{layers}`，T-16 另带框架键 `{group_id}`；T-2 的 `{layers,telnet}` 是专门验证 presence 门的非法负例）
> 白话一句：**十七条检查：十四条看正常收发（默认剧本、五个登录/命令场景、大输出分段、中断、二进制转义、子协商、banner、新网段、端口三态），三条看胡来能不能被拦下；每条只查一件事。**

## 1. 测试原则和形状基线

用例从设计 §3–§9 逐项派生，共 **17 个唯一语义 ID：14 正 + 3 负**（负例 N-1/N-2/N-3）。派生规则：设计 §3 每个编码条款、§5 每个事务/自动派生行为、§7 每行错误处理在本文有对应断言；断言不得超出设计声明范围。**一个用例只验证一个协议行为**。

**形状基线（2026-09-29 机读实测）**：

| 项 | 实测 |
|---|---|
| 顶层键 | 17/17 = `{expect,id,proto,spec_json,summary}`（+`strategy_fc` ×1 于 T-16） |
| `spec_json` 顶层键 | 合法正例：`{layers}` ×13 + `{layers,group_id}` ×1（T-16，`group_id` 是框架键）；非法负例：`{layers,telnet}` ×1（T-2 presence 门）+ `{layers}` ×1（T-3 静态四元组门） |
| 层形 | `[ip,telnet]` ×17（**无 `[ip,tcp,telnet]`**——raw-IP 自驱终层） |
| 端口 | `src_port=12345`/`dst_port=23` 显式 **×12**；T-15 无端口键（测缺省补齐）；T-16 端口动态对象（inc/fixed） |
| 正例包数形状 | **`packet_count` ×14**（精确包数） |
| 负例 expect 键 | 3/3 = `{expect_error, error_contains}`（严格两键） |

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`tcp.flags`、`tcp.dstport`/`srcport`、`tcp.len`、`telnet.data`、offset 54/74 frames）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；**不设仅单路径可用的断言**。

**TSHARK 基线（2026-09-29 实测，设计 §9.1）**：本机 tshark **3.6.14 有 telnet dissector**——`tshark -G fields` 中 `telnet.*` 字段 **58 个**（唯一名，`awk` 实测；`grep telnet` 的 78 行含 `mactelnet` 等噪声，不采），`tshark -G decodes` 有 `tcp.port 23 telnet`；14 个正例 pcap 全部被解码（1 个负例 pcap 0 帧）。可用字段通道：

| 通道 | 字段 | 实测形态 | 今日使用 |
|---|---|---|---|
| ① | `telnet.data` | FT_STRING，**三则伪影**（见下） | **2 例使用**（T-1 的 4 条 + T-4 的 1 条） |
| ② | `telnet.cmd` | FT_UINT8 **十进制**；多值逗号拼接 | **零使用**（A′） |
| ③ | `telnet.subcmd` | FT_UINT8 十进制；多值逗号拼接 | **零使用**（A′） |
| ④ | `telnet.string_subopt.value` | FT_STRING | **零使用**（A′） |
| ⑤ | `telnet.naws_subopt.width`/`.height` | FT_UINT16 十进制 | **零使用**（A′） |
| ⑥ | frames `offset/hex` | 原始字节 | **11 例使用（主通道）** |

**`telnet.data` 三则伪影（实测，G-TELNET-4）**：① IAC 帧输出**空串**（`ff fb 03` 帧 `telnet.data` 为空）；② **trim 尾部空白**（`login: ` → `"login:"`、`$ ` → `"$"`）；③ `\r\n` **显示为字面转义**（`"alice\\r\\n"`）。→ **字节面一律以 frames hex 断言为准**，`telnet.data` 只作辅助（存量先例口径）。

**进制纪律（实测）**：`telnet.cmd`/`telnet.subcmd`/`naws_subopt.*` 用**十进制串**；多值字段是**逗号拼接串**（`"250,240"`、`"24,1"`），单值断言不可直接 `==`（收编时须拆串）。

**断言基线（机读实测）**：**11 例**正例含 `frames`（共 **23 条 frame 断言，本车道逐条对实测 pcap 复核，全对**）；**2 例**含 `telnet.data` field 断言（T-1 ×4 + T-4 ×1）；共 **52 条 field 断言**（逐例：T-1 8 / T-4 4 / T-5 3 / T-6 3 / T-7 4 / T-8 3 / T-9 3 / T-10 3 / T-11 3 / T-12 3 / T-13 3 / T-14 3 / T-15 5 / T-16 4）；3 标量（`has_handshake`/`negotiated`/`terminates`）**仅 T-1** 用；**`tcp.len` 断言仅 1 条**（T-7 p25=1460，MSS 分段合同）。**3 例无 frames 断言**（T-7 只有 fields、T-15 只有 fields、T-16 只有 fields）。

**包数约定（实测公式，设计 §9）**：单流 = **3（握手）+ Σ 事件段数 + 4（挥手）**，`Σ 事件段数 = Σ ceil(payload_i / 1460)` 对 banner/file_source/dialog 每个数据事件求和（IAC 命令恒 1 段）。负例无包数断言（实测 0 帧）。

**`packet_count` 口径（实测）**：`pcaptest.verify.go:26-37` —— `packet_count` 是**精确等值**（`n != want` 即红），`min_packets` 是**下界**（`n < want` 才红）；本文件正例不再使用 `min_packets`。**14 例**正例均用 `packet_count` 精确断言，多发或少发均红。

**保活/重试/RST 口径**：**Telnet 无协议级保活**（无 PING/心跳；NOP 是"空操作"命令，不是心跳）——显式不适用，不设正例亦不得进负例；无重试/重连概念（剧本回放）；**RST 为框架 tcp 层能力，本层零断言** → A′ 补例（G-TELNET-8）；正例恒 FIN 优雅终止（4 包挥手）。

**动态字段禁止硬编码**：生成期随机值（`clientSeq`/`serverSeq`/`ipID`，`telnet.go:206-222`）**一律不断言**（设计 §6 断言边界）；T-16 用逐流端口断言（`tcp.srcport` 20000/20001 分帧钉）。

## 2. 原子用例索引（17 ID = 14 正 + 3 负，顺序为权威）

| # | ID | 类型 | 覆盖（设计 §） | 包数（实测 pcap） |
|---:|---|---|---|---:|
| 1 | `telnet_basic_session` | 正 | §3.1/§5：默认剧本 6 事件基线 | **13** |
| 2 | `telnet_flat_presence` | 负 | §7 N-1：顶层 `telnet:{}` presence 判死 | 0 |
| 3 | `telnet_flat_static_port` | 负 | §7 N-2：静态端口 + flows=2 拒 | 0 |
| 4 | `telnet_login_full` | 正 | §5：`login_full` 场景（26 事件段） | **33** |
| 5 | `telnet_login_fail` | 正 | §5：`login_fail` 失败路径（20 段） | **27** |
| 6 | `telnet_multi_command` | 正 | §5：`multi_command` + 双命令（26 段） | **33** |
| 7 | `telnet_long_output` | 正 | §3.6/§6：8196B 跨 MSS 6 段（29 段） | **36** |
| 8 | `telnet_option_reject` | 正 | §3.5：DONT/WONT 拒绝路径（21 段） | **28** |
| 9 | `telnet_synch` | 正 | §3.1：IAC IP + IAC DM 中断（31 段） | **38** |
| 10 | `telnet_iac_escape` | 正 | §3.3：`data_b64` 0xFF 翻倍 | **8** |
| 11 | `telnet_sb_subneg` | 正 | §3.4：`sb` 框架 + `sub_data_b64` 0xFF 翻倍 | **8** |
| 12 | `telnet_ttype_naws_singles` | 正 | §3.4/§3.1：ttype/naws 缺省 + 7 单命令枚举 | **16** |
| 13 | `telnet_banner` | 正 | §5：banner + file_source 前置 | **15** |
| 14 | `telnet_v6` | 正 | §2/§8：IPv6 独立用例（offset 74） | **13** |
| 15 | `telnet_default_port` | 正 | §8：端口缺省 → 23 | **13** |
| 16 | `telnet_port_dyn` | 正 | §12.12：端口动态 inc × flows=2 | **26**（`packet_count` 精确） |
| 17 | `telnet_neg_scenario` | 负 | §7 N-3：未知 scenario 白名单拒 | 0 |

**T-编号对照（与 `TEST_CASES.md` §T-TELNET 一致）**：T-TELNET-1 ≡ #1；T-2 ≡ #2；T-3 ≡ #3；T-4 ≡ #4；T-5 ≡ #5；T-6 ≡ #6；T-7 ≡ #7；T-8 ≡ #8；T-9 ≡ #9；T-10 ≡ #10；T-11 ≡ #11；T-12 ≡ #12；T-13 ≡ #13；T-14 ≡ #14；T-15 ≡ #15；T-16 ≡ #16；T-17 ≡ #17。（序号以 cases JSON 顺序为权威。）

**包数与实测 pcap 逐例一致**（本车道 `tshark -r … | wc -l` 实测，2026-09-29）：**14 例精确等值**（T-1 13 / T-4 33 / T-5 27 / T-6 33 / T-7 36 / T-8 28 / T-9 38 / T-10 8 / T-11 8 / T-12 16 / T-13 15 / T-14 13 / T-15 13 / T-16 26）。3 负例实测 **0 帧**。

## 3. 正例逐项断言契约（最低断言集，实现期可增不可减）

每例含包数断言 + frames 断言；**帧位与字节均由实测 pcap 逐帧复核**（offset 54 = IPv4 / 74 = IPv6）。

### 3.1 `telnet_basic_session`（13，`packet_count:13`）

`layers[1].telnet = {src_port:12345, dst_port:23}`（无 dialog → 默认剧本 6 事件）。

- **标量**：`has_handshake=true`、`negotiated=true`、`terminates=true`、`packet_count=13`。
- **fields（8 条）**：p1 `tcp.flags=0x002` / p1 `tcp.dstport=23` / p2 `tcp.flags=0x012` / p3 `tcp.flags=0x010` / p6 `telnet.data="login:"` / p7 `telnet.data="alice\\r\\n"` / p8 `telnet.data="$"` / p9 `telnet.data="exit\\r\\n"`。
- **frames（6 条，offset 54）**：p4 `ff fb 03`（IAC WILL SGA）/ p5 `ff fd 03`（IAC DO SGA）/ p6 `6c 6f 67 69 6e 3a 20`（`login: `）/ p7 `61 6c 69 63 65 0d 0a`（`alice\r\n`）/ p8 `24 20`（`$ `）/ p9 `65 78 69 74 0d 0a`（`exit\r\n`）。
- **包数证据**：3 + 6（默认剧本 6 事件）+ 4 = 13 ✓。
- **`packet_count:13` 精确钉住实测 13 包。**
- **存量注释纠错（notes 已记载）**：p4 `ff fb 03` 是 **WILL SGA**（选项 3），不是旧稿注释写的"Will Echo"；错误注释未迁移 ✓。

### 3.2 `telnet_flat_presence`（负，N-1）

`spec_json = {"layers":[{ip},{telnet{ports}}], "telnet":{}}`（**层链 + 顶层空子映射并存**）。

- `expect = {expect_error:true, error_contains:"top-level telnet sub-config"}`。
- **锚词证据（代码逐字）**：`strategy_convert.go:8961-8963` —— `protocol telnet no longer accepts a top-level telnet sub-config (move it into the telnet layer of an [ip,telnet] layers chain)`；**空 map 也判死**（`v != nil` 判定，`{}` 非 nil）。
- **时机**：create-time（400）。
- **形状说明（CORE_MEMORY presence-negative-case-shape 口径）**：此形状是**判死执法对象**，不是旧键残留——层链本身合法，顶层 `telnet` 子映射触发门。**该形状必须点名**。

### 3.3 `telnet_flat_static_port`（负，N-2）

`spec_json = {"layers":[{ip:{}},{telnet{src_port:12345,dst_port:23}}]}` + `strategy_fc = {type:"flows", value:2}`。

- `expect = {expect_error:true, error_contains:"static four-tuple"}`。
- **锚词证据（代码逐字）**：`schema/semantic.go:285` —— `layers pin a static four-tuple but flows > 1: every flow would emit identical addresses/ports (static copy). Write the varying field as a dynamic object inside its layer (ip.src/ip.dst, tcp/udp src_port/dst_port)`。
- **形状说明**：`ip` 层为空（对门无贡献）的最小证明形（h323/mpls/ngap T-3 同构）；telnet 层端口**静态标量** + `flows=2` 即触发。
- **时机**：create-time（400）。

### 3.4 `telnet_login_full`（33，`packet_count:33`）

`scenario="login_full"`、`username="bob"`、`password="hunter2"`、`terminal_type="vt100"`、`window_cols=200`、`window_rows=60`（**5 个场景参数键全显式**）。

- **fields（4 条）**：p1 `tcp.flags=0x002` / p2 `0x012` / p3 `0x010` / p17 `telnet.data="Password:"`。
- **frames（4 条，offset 54）**：p4 `ff fb 01`（WILL ECHO）/ p5 `ff fd 01`（DO ECHO）/ p15 `6c 6f 67 69 6e 3a 20`（`login: `）/ **p20 `68 75 6e 74 65 72 32 0d 0a`（`hunter2\r\n`）**。
- **包数证据**：3 + 26（11 协商 + 8 登录 + 1 `$` + 2×2 命令 + 2 logout）+ 4 = 33 ✓。
- **实测帧位表（本车道复核）**：p4/p5 WILL/DO ECHO(1)、p6/p7 WILL/DO SGA(3)、p8/p9 WILL/DO TTYPE(24)、p10/p11 WILL/DO NAWS(31)、p12 SB TTYPE SEND(`250,240`/`24,1`)、p13 SB TTYPE IS `vt100`（11B）、p14 SB NAWS 200×60（9B）、p15 `login: `、p16 `bob\r\n`、p17 `Password: `、p18 WONT ECHO（服务器关回显）、p19 DONT ECHO、p20 `hunter2\r\n`、p21 WILL ECHO（恢复）、p22 DO ECHO、p23 `$ `、p24 `ls -la\r\n`、p25 目录回显（57B）、p26 `whoami\r\n`、p27 `alice\r\n$ `（9B）、p28 `exit\r\n`、p29 `logout\r\n`。
- **场景参数键证据（全消费面）**：`username`→p16 `bob`；`password`→p20 `hunter2`；`terminal_type`→p13 `vt100`（实测 `telnet.string_subopt.value=vt100`）；`window_cols/rows`→p14 NAWS 200×60（实测 `telnet.naws_subopt.width=200`/`height=60`）。
- **失败路径覆盖（echo 关开）**：p18/p19（WONT/DONT ECHO）与 p21/p22（WILL/DO ECHO）是**密码输入期关回显、输入后恢复**的 RFC 857 现网语义——**该对比对本用例是正向序列的一部分**，非拒绝路径（拒绝路径在 #8）。

### 3.5 `telnet_login_fail`（27，`packet_count:27`）

`scenario="login_fail"`（**仅场景名，无参数键** → 全走场景默认 `alice`/`secret123`）。

- **fields（3 条）**：p1/p2/p3 `tcp.flags` 三态。
- **frames（1 条，offset 54）**：**p23 `4c 6f 67 69 6e 20 69 6e 63 6f 72 72 65 63 74 0d 0a 6c 6f 67 69 6e 3a 20`**（`Login incorrect\r\nlogin: `，24B）。
- **包数证据**：3 + 20（11 协商 + 8 登录 + 1 重提示）+ 4 = 27 ✓。
- **失败分支证据**：服务器拒认证后**重新提示**（`login: ` 尾随），`scenario.go:187` `"Login incorrect\r\nlogin: "` 逐字对应；本用例覆盖 CORE_MEMORY §9.9 的"异常分支"面。
- **实测帧位**：p4–p14 协商同 #4（默认参数）、p15 `login: `、p16 `alice\r\n`、p17 `Password: `、p18/p19 WONT/DONT ECHO、p20 `secret123\r\n`、p21/p22 WILL/DO ECHO、**p23 拒绝重提示**、p24–p27 挥手。

### 3.6 `telnet_multi_command`（33，`packet_count:33`）

`scenario="multi_command"`、`commands=["uname","pwd"]`（**显式双命令**）。

- **fields（3 条）**：p1/p2/p3 `tcp.flags`。
- **frames（1 条，offset 54）**：**p25 `4c 69 6e 75 78 20 68 6f 73 74 20 35 2e 31 30 2e 30 20 23 31 20 53 4d 50 20 78 38 36 5f 36 34 20 47 4e 55 2f 4c 69 6e 75 78 0d 0a`**（`Linux host 5.10.0 #1 SMP x86_64 GNU/Linux\r\n`，45B）。
- **包数证据**：3 + 26（11 + 8 + 1 + 2×2 + 2）+ 4 = 33 ✓。
- **多动作组合流证据（CORE_MEMORY §9.11）**：两条命令（`uname`/`pwd`）+ 各带 canned 回显 + 各带回显后提示符，同例内 ≥3 个不同动作（登录 / 命令 1 / 命令 2 / logout）✓。
- **canned 回显面证据**：p24 `uname\r\n` → p25 `Linux host …\r\n`（`commandResponse` 的 `uname*` 分支，`scenario.go:322-323`）；p26 `pwd\r\n` → p27 `/home/alice\r\n$ `（`pwd*` 分支，`scenario.go:324-325`）——**两命令回显可区分**，非重复同一段。

### 3.7 `telnet_long_output`（36，`packet_count:36`）

`scenario="long_output"`。

- **fields（4 条，无 frames 断言）**：p1/p2/p3 `tcp.flags` + **p25 `tcp.len=1460`**（MSS 分段合同）。
- **包数证据**：3 + 29（11 + 8 + 1 + 1 命令 + **6 大响应段** + 2）+ 4 = 36 ✓。
- **分段证据（实测）**：大响应 = `Repeat("A",8192) + "\r\n$ "` = **8196 字节**（`scenario.go:238`，`scenarioLongOutputBytes=8192`）→ `ceil(8196/1460)` = **6 段**：p25–p29 各 1460（5 段）+ p30 **896**（末段）= 5×1460 + 896 = 8196 ✓。
- **frame 位（实测）**：p24 `cat bigfile.txt\r\n`（17B）→ p25–p30 大响应 6 段 → p31 `exit\r\n` → p32 `logout\r\n`。
- **文案已按实测收敛**：summary 为 **8196B**；notes 只保留实测大响应首段 **p25**，不再混入过时的 p22 推算。
- **角色文案已按实测修正**：p6（src=12345 客户端口）WILL 39 → p7（src=23 服务器口）DONT 39，即**客户端提议 NEW-ENVIRON、服务器拒绝**；p8（src=23）WILL 34 → p9（src=12345）DONT 34，即**服务器提议 LINEMODE、客户端拒绝**。

### 3.8 `telnet_option_reject`（28，`packet_count:28`）

`scenario="option_reject"`。

- **fields（3 条）**：p1/p2/p3 `tcp.flags`。
- **frames（2 条，offset 54）**：**p7 `ff fe 27`**（IAC DONT NEW-ENVIRON=39=0x27）/ **p9 `ff fe 22`**（IAC DONT LINEMODE=34=0x22）。
- **包数证据**：3 + 21（10 协商 + 11 登录面）+ 4 = 28 ✓。
- **拒绝路径证据（RFC 855 §3）**：实测帧位 p4/p5 WILL/DO SGA(3)（**接受**）、p6 WILL NEW-ENVIRON(39) → **p7 DONT 39（拒绝）**、p8 WILL LINEMODE(34) → **p9 DONT 34（拒绝）**、p10/p11 WILL/DO TTYPE(24)（接受）→ p12 SB TTYPE SEND → p13 SB TTYPE IS → p14 NAWS。**两条拒绝路径 + 一条接受路径同例对照** ✓。
- **角色文案已按实测修正**：p6（src=12345 客户端口）WILL 39 → p7（src=23 服务器口）DONT 39，即**客户端提议 NEW-ENVIRON、服务器拒绝**；p8（src=23）WILL 34 → p9（src=12345）DONT 34，即**服务器提议 LINEMODE、客户端拒绝**。

### 3.9 `telnet_synch`（38，`packet_count:38`）

`scenario="synch"`。

- **fields（3 条）**：p1/p2/p3 `tcp.flags`。
- **frames（2 条，offset 54）**：**p30 `ff f4`**（IAC IP=244）/ **p31 `ff f2`**（IAC DM=242）。
- **包数证据**：3 + 31（11 协商 + 8 登录 + 1 `$` + 1 `yes` + **5 y 输出段** + ip + dm + `^C\r\n$ ` + exit + logout）+ 4 = 38 ✓。
- **中断证据（本车道跑码探针 + pcap 双向核对）**：y 输出 = `Repeat("y\r\n",2000)` = **6000 字节**（`"y\r\n"` 是 **3** 字节/单元 × 2000，`scenario.go:299`）→ `ceil(6000/1460)` = **5 段**（实测 p25/p26/p27/p28 各 1460 + p29 **160** = 4×1460+160 = 6000 ✓）。p30 = IP、p31 = DM、p32 `^C\r\n$ `、p33 `exit\r\n`、p34 `logout\r\n`。
- **`synch` 事件类型未覆盖（G-TELNET-11）**：本用例用的是**分离的** `ip` + `dm` 两个事件（`scenario.go:301-302`），`renderTelnetEvent` 的 `case "synch"`（合并 4 字节形，`telnet.go:477-481`）**零用例**。
- **DM 无 URG（C 类注记）**：RFC 854 §3 要求 DM 段置 TCP URG，本实现不设（`telnet.go:478-481` 自认，`core.L4Config` 无 `UrgentPointer` 字段）→ 不得断言 `tcp.urgent_pointer`（G-TELNET-6）。

### 3.10 `telnet_iac_escape`（8，`packet_count:8`）

`dialog=[{type:"data", direction:"up", data_b64:"Yf8gYg=="}]`。

- **fields（3 条）**：p1/p2/p3 `tcp.flags`。
- **frames（1 条，offset 54）**：**p4 `61 ff ff 20 62`**（5B）。
- **IAC 转义证据（RFC 854 §3 核心）**：base64 `Yf8gYg==` 解码 = `61 ff 20 62`（`a`、0xFF、空格、`b`）→ `escapeIAC` 把 0xFF 翻倍 → **`61 ff ff 20 62`** ✓。
- **为何必须走 `data_b64`（notes 逐字）**：JSON 字符串无法表达单字节 0xFF——写 `"ÿ"` 会被 UTF-8 重编码成 `c3 bf`，转义后成 `c3 bf c3 bf`，与意图不符。**这是本用例存在的唯一理由**。

### 3.11 `telnet_sb_subneg`（8，`packet_count:8`）

`dialog=[{type:"sb", direction:"up", option:39, sub_data_b64:"eP8="}]`。

- **fields（3 条）**：p1/p2/p3 `tcp.flags`。
- **frames（1 条，offset 54）**：**p4 `ff fa 27 78 ff ff ff f0`**（8B）。
- **SB 框架证据（§3.4）**：`IAC SB`(`ff fa`) + `option 0x27`(=39 NEW-ENVIRON) + 子数据 `78 ff ff`（`x` + 0xFF 翻倍）+ `IAC SE`(`ff f0`) ✓——**长度 = 3 + 3 + 2 = 8** ✓。
- **子数据转义证据**：`sub_data_b64="eP8="` 解码 = `78 ff`（`x`、0xFF）→ 翻倍 `78 ff ff` ✓（**与 data 转义同一函数，两处承载位置各有一例** = CORE_MEMORY §9.22 口径）。

### 3.12 `telnet_ttype_naws_singles`（16，`packet_count:16`）

`dialog` 9 事件：`ttype_is`（**无 value**）、`naws`（**无 cols/rows**）、`nop`、`ayt`、`brk`、`ao`、`ec`、`el`、`ga`（**全 direction:"up"**）。

- **fields（3 条）**：p1/p2/p3 `tcp.flags`。
- **frames（2 条，offset 54）**：**p4 `ff fa 18 00 78 74 65 72 6d ff f0`**（11B = `IAC SB TTYPE IS "xterm" IAC SE`）/ **p5 `ff fa 1f 00 50 00 18 ff f0`**（9B = `IAC SB NAWS 80×24 IAC SE`）。
- **包数证据**：3 + 9 + 4 = 16 ✓。
- **缺省值三级兜底证据**：`ttype_is` 无 `value` → 事件 `Value` 空 → `TelnetConfig.TerminalType` 空（本层 config 无该键）→ 常量 `"xterm"`（`telnet.go:415-421`）✓；`naws` 无 `cols/rows` → 事件 0 → config 0 → 常量 80×24（`telnet.go:435-448`）✓。`00 50`=80、`00 18`=24（**大端**）✓。
- **七单命令枚举（CORE_MEMORY §9.20，notes 钉全）**：**p6 `ff f1`**（NOP=241）/ **p7 `ff f6`**（AYT=246）/ **p8 `ff f3`**（BRK=243）/ **p9 `ff f5`**（AO=245）/ **p10 `ff f7`**（EC=247）/ **p11 `ff f8`**（EL=248）/ **p12 `ff f9`**（GA=249）——**七值一例全覆盖，逐字节钉死** ✓（本车道实测 p12 offset 54 = `ff f9` 复核通过）。
- **枚举覆盖裁定（notes 逐字，`TEST_CASES.md` 口径）**：19 事件类型中剩余 7 个单字节命令"一处覆盖七枚举"——**该裁定成立**（7 个分支各自独立，字节互异，同例内可逐条断言）。

### 3.13 `telnet_banner`（15，`packet_count:15`）

`banner="Welcome\r\n"`、`file_source={literal:"pay"}`（**无 dialog** → 默认剧本 6 事件）。

- **fields（3 条）**：p1/p2/p3 `tcp.flags`。
- **frames（2 条，offset 54）**：**p4 `57 65 6c 63 6f 6d 65 0d 0a`**（`Welcome\r\n`，9B，**down** 方向）/ **p5 `70 61 79`**（`pay`，3B，**up** 方向）。
- **包数证据**：3 + 1 banner + 1 file + 6 默认剧本 + 4 = 15 ✓。
- **前置顺序证据（设计 §5）**：banner 在**握手后立即**（`telnet.go:291-294`，down）→ file_source 紧随（`:297-304`，**up**）→ dialog（`:307-327`）。**banner 是 down、file_source 是 up**，方向可直接由 `tcp.srcport` 区分（实测 p4 src=23、p5 src=12345）✓。
- **`file_source` 两形态（§10.3 #25/#26）**：本用例覆盖 `literal` 形态；`file` 形态（走 `PayloadCache.GetOrLoad`）**零用例** → A′ 立项。

### 3.14 `telnet_v6`（13，`packet_count:13`）

`layers[0].ip = {src:"fd00::1", dst:"fd00::2"}`、`telnet{ports}`（无 dialog）。

- **fields（3 条）**：p1 `tcp.flags=0x002` / p1 `tcp.dstport=23` / p2 `tcp.flags=0x012`。
- **frames（1 条，offset 74）**：**p4 `ff fb 03`**（同 #1 的 p4，**字节完全相同，只有起点从 54 变 74**）。
- **地址族证据（CORE_MEMORY §9.24）**：`eth.type=0x86dd`（实测）、`ipv6.src=fd00::1`/`dst=fd00::2`（实测）；**事件字节面与 v4 完全同构**（p4 `ff fb 03` 逐字节相同）——**telnet 无 IP 版本强制**（`telnet.go:124-157` 无族校验），故 **v6 = 正例格**（与 ngap 的 v6 负例格语义相反）。
- **offset 74 = 14（Eth）+ 40（IPv6）+ 20（TCP）** ✓。

### 3.15 `telnet_default_port`（13，`packet_count:13`）

`layers[1].telnet = {}`（**空层配置，无端口键**）。

- **fields（5 条，无 frames 断言）**：p1 `tcp.dstport=23`（**缺省补齐证据**）/ p1 `tcp.flags=0x002` / p2 `tcp.dstport=12345`（**down 方向 dst = 客户端口，即 worker 保底值**）/ p2 `tcp.flags=0x012` / p3 `tcp.flags=0x010`。
- **包数证据**：空 config → translate 填非 nil 空 `TelnetConfig` → `len(dialog)==0` → 默认剧本 6 事件 → 3 + 6 + 4 = 13 ✓。
- **缺省证据（设计 §8）**：`chain_planner_translate.go:1647-1651` —— `dst_port` 缺席 → `spec.DstPort = 23`（镜像 `setDefaultDstPort(&spec, cfg, 23)`，`strategy_convert.go:1540`，RFC 854 IANA）；`src_port` 缺席 → **不动**（链路径保持 0，`chain_planner.go:996` 豁免名单），worker 按 `12345+i` 保底（`strategy_convert.go:49`）→ 实测 p1 src=12345 ✓。
- **双向端口证据**：p1（up）`dst=23`、p2（down）`dst=12345`——**端口对换直接可见** ✓。

### 3.16 `telnet_port_dyn`（26，**`packet_count:26` 精确**；fields 4 条，无 frames 断言）

`ip.src` = inc 策略（`["10.0.1.1","10.0.1.2"]` step 1）、`telnet.src_port` = inc（`[20000,20001]` step 1）、`telnet.dst_port` = fixed 23、`strategy_fc={type:"flows",value:2}`、顶层 `group_id={strategy:"fixed",value:"telnet-port-dyn"}`。

- **fields（4 条）**：p1 `tcp.srcport=20000` / p1 `tcp.dstport=23` / **p14 `tcp.srcport=20001`** / p14 `tcp.dstport=23`。
- **多流证据（CORE_MEMORY §9.32–9.35）**：流 1 = p1–p13（`srcport=20000`、`ip.src=10.0.1.1`）、流 2 = p14–p26（`srcport=20001`、`ip.src=10.0.1.2`）——**2 流 × 13 = 26** ✓，**逐流端口/地址可观察且可区分** ✓。
- **`group_id` 固定单 worker FIFO 证据（notes）**：`group_id` 固定值使两流落到**同一 worker**，故回放严格串行（p1–p13 后 p14），帧位可钉——h323/mpls/ngap T-16 先例同款。
- **序号算法证据（设计 §12.12）**：`layer_dyn.go:62` allowlist telnet 端口 2 键开 → `:252` parseLayerDyn 填 `LayerDynValues.TELNET` → `:846-856` `resolveLayerTuple` 逐流解析落 `spec.SrcPort`/`spec.DstPort`（`ResolvePortValue(dyn, i)`，`i` = 流序号）✓。
- **本用例使用 `packet_count:26` 精确断言**；全部 14 个正例现均为精确包数。

### 3.17 `telnet_neg_scenario`（负，N-3）

`layers[1].telnet = {…, scenario:"telnet999"}`。

- `expect = {expect_error:true, error_contains:"unknown scenario"}`。
- **锚词证据（代码逐字）**：`scenario.go:58` —— `telnet: unknown scenario %q (want login_full/login_fail/multi_command/long_output/option_reject/synch)`；**白名单 6 值**（`scenario.go:54-55`）。
- **时机**：**task-time**（`Planner.Validate` 内，`telnet.go:151-155`）——与前两条 create-time 负例**时机不同**，这是本协议三类负例的**三个不同执法层**（presence 门 / 静态门 / 协议 validator）✓。

**正例总则**：默认剧本、6 场景、多命令、大输出分段、选项拒绝、中断、二进制转义、子协商、banner、v6、端口三态均为正例形态；只有配置错（presence/静态复制）与协议参数错（scenario 白名单）进入负例。

## 4. 负例契约

负例必须在对应执法层失败并传播为 task error，不得产生成功 PCAP、`completed/0 packet` 或只剩 TCP 外壳的假成功（**实测 3 例 pcap 均 0 帧**，文件名 `<id>.neg.pcap`——实测仅 `telnet_neg_scenario.neg.pcap` 落盘，另两例 create-time 拒绝无 pcap）。锚词与设计 §7 表一一对应、同序（代码逐字）：

| ID | 故障输入（机读实测） | JSON `error_contains` | 代码文案（逐字） | 代码行 | 时机 |
|---|---|---|---|---|---|
| `telnet_flat_presence` | `{"layers":[…],"telnet":{}}` | `top-level telnet sub-config` | `protocol telnet no longer accepts a top-level telnet sub-config (move it into the telnet layer of an [ip,telnet] layers chain)` | `strategy_convert.go:8961-8963` | create-time |
| `telnet_flat_static_port` | `[ip{},telnet{静态端口}]` + `flows=2` | `static four-tuple` | `layers pin a static four-tuple but flows > 1: every flow would emit identical addresses/ports (static copy). …` | `schema/semantic.go:285` | create-time |
| `telnet_neg_scenario` | `scenario:"telnet999"` | `unknown scenario` | `telnet: unknown scenario %q (want login_full/login_fail/multi_command/long_output/option_reject/synch)` | `scenario.go:58` | task-time |

**锚词口径**：`error_contains` 是**子串**判定；三例均命中代码文案。

**负例原子性**：每例单一故障注入；单次执行不得混注。三例 `expect` 键集合严格为 `{expect_error, error_contains}`，与 C4 两键契约一致。

**expect 键形状注**：`pcaptest.VerifyPcap` 对 `expect_error` 用例**直接返回无问题**（`verify.go:21-24`）——即负例的"通过"只证明**任务按预期失败**，不校验 pcap 内容（负例本就不产 pcap）✓ 语义正确。

**未入用例的拒绝分支（不得冒充已覆盖）**：4 个分支在链路径**不可达**——`telnet: SrcIP %q is not a valid IP address`（`telnet.go:127`）/ `DstIP %q is not a valid IP address`（`:132`，两者被 schema 格式门先拦）/ `TCP.MSS %d too small (min %d per RFC 879)`（`:138`）/ `TCP.MSS %d too large (max 65535)`（`:141`，两者因 `spec.TCP` 恒 nil 不可达）。**四个锚词今日是"零死锚词"**（C 类注记，G-TELNET-9）——不得建负例（建了必然真绿 = 假通过）。

**未入用例的静默路径（非缺陷，设计口径）**：未知事件 `Type` → 不产帧（`telnet.go:483-486`）；空 `data` → 不产帧（`:314-317`）；`direction` 非法 → 归 `"up"`（`:319-321`）。三者均为**设计声明的合法行为**（不是错误），今日无 JSON 用例（单测覆盖）→ A′ 立项（§6.2）。

## 5. 覆盖与对账

### 5.1 三源回指行

RFC 854（NVT + IAC §3）+ RFC 855（选项协商/SB）+ RFC 857/858/1073/1091/856/859/860/1079/1184/1372/1572（选项码出处）+ **RFC 1143（要求面，未实现）**（设计 §10）+ D-TELNET-1（设计 §11）+ tshark 3.6.14 `telnet.*` 字段表（**58 字段**）与 **15 例实测 pcap**（`/tmp/mcp-pcaps/telnet/`）→ 17 ID（本契约 §2）。第三源"已确认现网行为"当前 = **抓包级已到**（本仓引擎产出的 15 例 pcap 逐帧复核），但**真实 telnetd 的线字节未取到** → G-TELNET-13（按 §5.5 不写死进实现）。

**17 ID 逐项回指（§9.5 要求）**：#1←设计 §3.1/§5；#2←§7 N-1；#3←§7 N-2；#4←§5；#5←§5；#6←§5；#7←§3.6/§6；#8←§3.5；#9←§3.1；#10←§3.3；#11←§3.4；#12←§3.4/§3.1；#13←§5；#14←§2/§8；#15←§8；#16←§12.12；#17←§7 N-3。

### 5.2 对账两行 + 清单出处声明

- **清单出处声明**：本清单来源 = **RFC 854/855 族公开语义 + RFC 1143（要求面）+ `TEST_CASES.md` §T-TELNET 已验收清单 + 仓库落码反推 + tshark 3.6.14 字段与 15 例 pcap 实测**，**非纯规范反推**（真实 telnetd 线字节未取到 → G-TELNET-13；RFC 1143 条款号未逐条核对）。
- **对账两行**：**要求逻辑点总数 = 128**（八项 8 行 + 矩阵 63 格 + 变体 33 行 + 商业映射 16 行 + 事件类型 21 行**已并入矩阵 63 格**，不重复计 → 8 + 63 + 33 + 16 = 120；**加 8 个 ts/harness 面**（tshark 四通道收编 / RST / 非默认端口 / 边界相邻值 / 截断溢出 / 默认端口 / FIN 优雅终止 / 多流并发）= **128**）；**用例覆盖数 = 80**（八项已覆 5 + 矩阵已覆 20 + 变体已覆 26 + 商业已覆 12 + ts 面已覆 17）；**不适用 = 23**（八项 2 + 矩阵 21）；**开放立项 = 25**（八项 1 + 矩阵 22 + 变体 7 − 与 ts 面重叠的 5 项 = 25）。80 + 23 + 25 = 128 ✓
  **粒度声明**：行/格粒度每点 1 计；G-TELNET-1…G-TELNET-17 不折进 128。**反查全绿 ≠ 覆盖全**（§9.52 原文）。逐表重数见设计 §10.1（八项 8 = 覆 5 + 立项 1 + 不适用 2）/§10.2（63 格 = 覆 20 + 立项 22 + 不适用 21）/§10.3（33 行 = 覆 26 + 立项 7）/§10.4（16 行 = 覆 12 + 不适用 4）。8+63+33+16 = 120；+8 ts 面 = 128 ✓
- **门3 抽查候选**：最复杂用例 = **#9 `telnet_synch`**（38 帧：3 握手 + 11 协商 + 8 登录 + 1 `$` + 1 `yes` + **5 段长输出**（4×1460+160）+ **ip/dm 中断对** + `^C` 重提示 + exit + logout + 4 挥手；交织维度 = 事件类型(8)×方向(2)×分段(5)×地址族(1)）；**建议门3 抽 #9 + #4**（`login_full` 补 5 场景参数键 + echo 关开面）。

### 5.3 T-编号对照（设计 §9 全表摘要）

见 §2 对照行（T-TELNET-1…17 ≡ #1…#17，一一对应，无虚例）。

## 6. P3 固定动作（CORE_MEMORY 管线：§3.15 三项 + A′/B′ 两分类 + 3.14 豁免）

### 6.1 §3.15 三项逐项一例或立项

| # | 三项 | 本协议对照 | 用例/立项 |
|---|---|---|---|
| ① | 同连接/同流内的多轮操作 | 单 TCP 连接内多事件段（#4 26 段、#6 26 段、#7 29 段、#9 31 段）；多流（#16 2 流） | 已覆 #4/#6/#7/#9/#16 |
| ② | 非正常结束 | 正常终止 = FIN 四包挥手（全正例）；应用层中断 = IAC IP + IAC DM（#9）；传输异常 = RST（框架 tcp 层能力，本层零断言） | 已覆（挥手全正例 + #9 中断）；**RST A′ 立项**（G-TELNET-8） |
| ③ | 长保活 | **Telnet 无协议级保活**（无 PING/心跳；NOP 是"空操作"命令不是心跳） | **显式不适用**（如实声明，不设正例亦不得进负例）；#9 的 4 段长输出是**长传输**不是长保活 |

无空项：① 有已覆例；② 有已覆例 + 1 条 A′ 立项；③ 显式不适用 + 理由。

### 6.2 A′/B′ 两分类表

**A′（P4 接线）**：

| 类 | 内容 | 落点 |
|---|---|---|
| tshark 通道面 | 收编 `telnet.cmd`/`telnet.subcmd`/`string_subopt.value`/`naws_subopt.*` 四通道——今日零使用（**可用但未收编**） | G-TELNET-12 |
| 事件类型面 | `synch` 合并形（`ff f4 ff f2`）补例 | G-TELNET-11 |
| 字段形态面 | `sub_data`（非 b64）/ 事件级 `value` / `file_source.file` / 未知 `option` 码 | 设计 §10.3 #12/#14/#18/#26 |
| 静默路径面 | `direction` 非法 → up / 未知 `Type` → 不产帧 / 空 `data` → 不产帧 | 设计 §10.3 #20/#21/#22 |
| 断言强度面 | 14 例正例均为 `packet_count`（精确） | G-TELNET-16 |
| 非正常结束 | `tcp.rst` 补例 | ② 的 A′（G-TELNET-8） |
| 负例纯净面 | 3 例 `expect` 严格保留 `{expect_error,error_contains}` 两键 | C4 / G-TELNET-10 |
| 文案纠错面 | T-7 summary 8197→8196 + 删除过时 p22 推算；T-8 summary 方向描述按实测改写 | 已完成（G-TELNET-2 / G-TELNET-17） |
| NAWS 零值面 | `naws` 显式 0×0（须先改类型或加标志） | G-TELNET-7 |

**B′（框架面）**：顶层游离键通用门（G-TELNET-14，等框架级 unknown-key 白名单，**禁加单协议黑名单分支**）/ 业务字段动态 10 键（G-TELNET-12 的业务面，allowlist 无 telnet 业务行）/ `synch` DM 的 TCP URG 位（G-TELNET-6，`core.L4Config` 无 `UrgentPointer` 字段）/ 链路径 MSS 配置（G-TELNET-9，须先改 `layer_gen.go` 传 TCP）。进设计 §14，「明确不解决 + 迁入计划」。

### 6.3 3.14 豁免边界审计

**有长连接载体（TCP）→ `sessions[]` 不豁免**？——**本协议 `sessions[]` 显式不适用**：telnet 层 registry **12 键无 `sessions`**（机读实测），Telnet 是**单 TCP 连接上的字符流**（RFC 854 无多会话/多流概念）。多流由策略级 `strategy_fc {"type":"flows"}` 承载（#16 已覆 2 流）。**理由写清**：Telnet 协议本身无会话复用/多路复用机制（每个 telnet 连接 = 一个终端会话），故 `sessions[]` 无协议语义可挂。**多流并发**由 #16 承载（2 流各自完整剧本，串行整块回放）。**单包多载荷** = **不适用**（Telnet 每段一个数据块，无多 question/多 RR 类形态，如实声明）。

## 7. 实现后执行建议

1. **P4 文案与精确包数修订已落地**：T-7 summary/notes 与 T-8 summary 已按实测修正；3 个负例仍严格为 `{expect_error,error_contains}`。A′ 补例与全量复跑属于后续代码阶段，不在本次三文件文档修订范围内。
2. **实测顺序**：先 #1（默认剧本 13 帧 + WILL/DO SGA 基线），再 #10/#11（转义两处承载位置：`data_b64` 与 `sub_data_b64`），再 #12（ttype/naws 缺省 + 七单命令），再 #4/#5/#6（场景参数 + 失败路径 + 多命令），再 #7（MSS 6 段 + `tcp.len=1460`），再 #8/#9（拒绝路径 + 中断对），最后 #13（banner/file_source 前置顺序）、#14（v6 offset 74）、#15（缺省端口）、#16（多流端口）。
3. **门2 四项**：①顶层旧键零残留（非负例顶层键 = 0，**今日成立**）；②`CASE_PROTO=telnet` 全量不是增量，负例带锚词；③二进制与 HEAD 同代（`find trafficgen -name '*.go' -newer <server-binary>` 无输出）；④反查绿（`coverage_gate.py telnet`，本车道实测 **32/32 绿**）。
4. **服务端验证 = 服务器重编重启**（h323 教训）；pcap 落 `/tmp/mcp-pcaps/telnet/`。

## 8. 存量审计（17 例逐条去向）

### 8.1 存量实测面（2026-09-29）

`cases/telnet.json` **17 例**：14 正例带包数断言（`packet_count` 13/33/27/33/36/28/38/8/8/16/15/13/13/26），**与实测 pcap 帧数逐例一致**（`tshark -r … | wc -l`）；3 负例 `expect` 键集合 `{expect_error,error_contains}`，实测 **0 帧**；17/17 `spec_json` 顶层键 ∈ `{layers}` ∪ `{telnet(负例执法对象), group_id(框架键)}`；**23 条 frame 断言逐条对实测 pcap 复核（全对）**；层内 `telnet` 12 键与 registry Fields 逐键一致（机读实测）。

### 8.2 现状矛盾点（P4 前诚实登记）

1. **`packet_count` 精确断言（G-TELNET-16 已关闭）**：14 例正例均为 `packet_count` 精确断言，多发或少发均红；G-TELNET-16 已关闭。
2. **T-7 文案已修正**：summary 为 8196；notes 保留实测首段 p25，G-TELNET-2 已关闭。
3. **T-8 summary 角色已修正**：按实测区分客户端提议 NEW-ENVIRON、服务器提议 LINEMODE，G-TELNET-17 已关闭。
4. **`docs/protocol-pcap-test/telnet.md` pcap 目录缺失（G-TELNET-3）**：17 个包数**本车道复核全对**，但 `docs/protocol-pcap-test/telnet/` **不存在**，文档内 **15 处**链接全断。末次提交 `d58bef9`（2026-09-19）**晚于**判死提交 `0417be5`（2026-09-13），故**不适用** opcua G-OPCUA-10 的"过期产物"口径——本缺口是"**pcap 未留档 + 死链**"，归属**代码阶段**（P5 重跑套件后落盘）。本车道未跑该套件。
5. **tshark 四通道零使用（G-TELNET-12）**：`telnet.cmd`/`telnet.subcmd`/`string_subopt.value`/`naws_subopt.*` **实测可用**（58 字段 dissector 在案），17 例今日**只用 `telnet.data` + frames**。**不是被迫，是未收编**。
6. **`synch` 事件类型零用例（G-TELNET-11）**：`renderTelnetEvent` 的 `case "synch"` 分支无任何 JSON 用例走过（#9 用分离的 ip+dm）。
7. **RFC 1143 协商状态机未实现（G-TELNET-5）**：规范要求四态机（设计 §3.5 写全），本实现是无状态回放——**用例断言的是字节序列，不是"协商结果正确"**。
8. **NAWS 零值不可表达（G-TELNET-7）**：`uint16` 零值歧义 → `0×0` 发不出；`TestSB_NAWS_0x0` 用 `t.Logf` 而非断言（**弱断言**）。
9. **`design_telnet.md` 死引用（G-TELNET-15）**：`telnet.go`/`types.go`/`scenario.go` 共 9 处注释引用该文件，**全仓不存在**。
10. **D-TELNET-1 条目计数错（G-TELNET-1）**：`CODE_DESIGN.md` 两处写"registry 14 键"，实测 **12 键**。
11. **存量未覆盖**：`synch` 合并形、`sub_data` 原始形态、事件级 `value`、`file_source.file`、未知 `option` 码、`direction` 非法值、未知 `Type`、空 `data`、RST、NAWS 零值 —— **今日零用例**（A′ 补）。
12. **已排除的伪疑点（自审纠错记录）**：初稿曾据"p25–p29 段长合计 6000"推"`Repeat("y\r\n",2000)`=4000 与实测不符"——**该推算本身有误**（`"y\r\n"` 是 **3** 字节/单元，2000×3 = 6000）。本车道跑码探针实测 `synch` 38 帧 / down 6000+57 字节、`long_output` 36 帧 / down 8196+51 字节，**与 pcap 逐字节一致**；D-TELNET-1 §6 的"6/5 段"亦**正确**（6 = long_output / 5 = synch）。**该伪缺口已撤销，不登记**。

### 8.3 逐条去向表（17 行）

| 存量 id | T-编号 | 去向 | 改写动作（P4） |
|---|---|---|---|
| `telnet_basic_session` | T1 | **改写** | `packet_count:13`（已完成收窄）；可补 `telnet.cmd`/`telnet.subcmd` 断言（`251/3`、`253/3`）替代部分 frames |
| `telnet_flat_presence` | T2 | **保留** | 负例 `expect` 严格两键；形状已合规（presence 执法对象） |
| `telnet_flat_static_port` | T3 | **保留** | 负例 `expect` 严格两键 |
| `telnet_login_full` | T4 | **保留** | `packet_count:33` → `packet_count:33`；可补 `string_subopt.value=vt100` + `naws_subopt 200/60` 断言（G-TELNET-12） |
| `telnet_login_fail` | T5 | **保留** | `packet_count:27` → `packet_count:27` |
| `telnet_multi_command` | T6 | **保留** | `packet_count:33` → `packet_count:33` |
| `telnet_long_output` | T7 | **改写** | summary 8196；删 notes 首句过时 "p22" 推算，保留实测 p25；包数仍为 `packet_count:36` |
| `telnet_option_reject` | T8 | **改写** | summary 客户端/服务器角色按**实测**改写（G-TELNET-17）；包数仍为 `packet_count:28` |
| `telnet_synch` | T9 | **保留** | `packet_count:38` → `packet_count:38`；可补 `tcp.len` 分段断言（p25–p28=1460、p29=160，MSS 分段合同） |
| `telnet_iac_escape` | T10 | **保留** | `packet_count:8` → `packet_count:8` |
| `telnet_sb_subneg` | T11 | **保留** | `packet_count:8` → `packet_count:8`；可补 `telnet.subcmd=39` 断言 |
| `telnet_ttype_naws_singles` | T12 | **保留** | `packet_count:16` → `packet_count:16`；可补七单命令 `telnet.cmd` 断言（241/246/243/245/247/248/249） |
| `telnet_banner` | T13 | **保留** | `packet_count:15` → `packet_count:15` |
| `telnet_v6` | T14 | **保留** | `packet_count:13`（已收窄）；可补 `eth.type=0x86dd`/`ipv6.src` 断言 |
| `telnet_default_port` | T15 | **保留** | `packet_count:13`（已收窄） |
| `telnet_port_dyn` | T16 | **保留** | 已是 `packet_count`（精确）；可补 `ip.src` 逐流断言 |
| `telnet_neg_scenario` | T17 | **保留** | 负例 `expect` 严格两键 |

**无"作废不注原因"：0 作废，0 等价覆盖**（17 例全部保留/改写 + A′ 新增）。**本协议存量 17/17 无旧键残留**（与 opcua/moxa 等共多个协议同为纯层链形，**非全仓唯一**；见设计 §12.1 注）。

## 9. 附：覆盖反查门建议断言行（供主线程合后登记；本车道不碰 `coverage_gate.py`）

> **现状说明**：`coverage_gate.py` **已有 `check_telnet`**（`:703-738`，32 项），本车道实测 `python3 trafficgen/tools/coverage_gate.py telnet` → **32/32 绿**（exit 0）。下列为**增量建议**（现有 32 项之外的补强），每条均可从本契约与 cases JSON 直接机读，不需新造事实。

| # | 建议断言 | 依据 |
|---:|---|---|
| 1 | `len(cases['telnet']) == 17` 且 ID 集合 = §2 十七项，顺序一致 | 本契约 §2 |
| 2 | 17/17 例 `spec_json` 顶层键 ⊆ `{layers, group_id}`；T-2 的 `{telnet}` 游离键仅作为 presence 负例，T-3 的 `{layers}` 是静态四元组负例 | 本契约 §1；设计 §12.1 |
| 3 | 14 例正例 `packet_count` 与实测包数逐一相等 | 本契约 §1；G-TELNET-16 |
| 4 | T-16 `packet_count == 26` 且 `flows==2` → `26 == 2 × 13` | 本契约 §3.16 |
| 5 | 3 负例 `expect` 键 == `{expect_error, error_contains}`（严格两键） | 本契约 §4 |
| 6 | 负例 `error_contains` ∈ 代码锚词集 `{"top-level telnet sub-config", "static four-tuple", "unknown scenario"}` | 设计 §7 |
| 7 | 非负例顶层键计数 == 0（仅 `layers`，T-16 另计框架键 `group_id`）——**今日已成立** | 设计 §12.1 |
| 8 | 每正例至少一条 frames 断言落在 offset 54（IPv4）或 74（IPv6，仅 T-14） | 本契约 §3 |
| 9 | 无任何用例的 `expect.fields` 含 `telnet.data` 作**唯一**字节证据（须伴 frames 断言） | 本契约 §1（tshark 伪影纪律） |
| 10 | 17/17 例 `spec_json.layers` 末层名 == `"telnet"` 且链内**不含** `tcp`/`udp`（raw-IP 自驱约束） | 设计 §12.3 |
| 11 | T-12 `dialog` 含 7 个单命令类型（nop/ayt/brk/ao/ec/el/ga）且 frames 覆盖 p6–p12 | 本契约 §3.12 |

**另注意**：`trafficgen/docs/protocol-pcap-test/telnet.md` 的 17/17 pass **包数已复核全对**，但 `docs/protocol-pcap-test/telnet/` **目录不存在**（15 处链接全断）→ **不得据该文档认为 pcap 可查**（G-TELNET-3，归属代码阶段）。该缺口与 opcua G-OPCUA-10 **口径不同**：opcua 是"末次提交早于判死提交"（过期产物），telnet 是"**末次提交晚于判死提交、数字正确、但 pcap 未留档 + 死链**"——不得混用同一口径。

## 10. 修订记录

- v1.0.1（2026-10-01）：最终文案修订：T-7 summary/notes 改为实测 8196B 与 p25；T-8 summary 改为实测客户端/服务器提议方向；3 个负例 expect 保持严格两键。

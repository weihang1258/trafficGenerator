# #111 ldap（LDAP · RFC 4511）测试用例契约

> 版本：v1.0.0（批次二 as-built 文档轨）
> 日期：2026-09-29
> 配套设计：`docs/protocol-designs/111-ldap-design.md` v1.0.0（D-LDAP-1）
> 机器契约：`trafficgen/test/protocol_pcap/cases/ldap.json`（**22 例 = 16 正 + 6 负**；22/22 ID 与本版 §2 一致、顺序一致，已机读实测；**顶层键已是纯层链形，零残留**）
> 白话一句：**二十二条检查：十六条看正常收发（握手、bind 三形态、search 六形态、多轮、自定义栏位、会话结束两形态、复合场景），六条看胡来能不能被拦下；每条只查一件事。**

## 1. 测试原则和形状基线

用例从设计 §3–§9 逐项派生，共 **22 个唯一语义 ID：16 正 + 6 负**（负例 N-1…N-6）。派生规则：设计 §3 每个消息/字段条款、§5 每个事务/自动派生行为、§7 每行错误处理在本文有对应断言；断言不得超出设计声明范围。**一个用例只验证一个协议行为**。

**形状基线（2026-09-29 机读实测）**：22/22 例顶层键 = `{expect, id, proto, spec_json, summary}`；`spec_json` 顶层键 = **`{layers}` ×22（唯一键，零游离键、零顶层 `ldap` 子映射）**——本协议存量**顶层零残留**，无 §1 迁移工作量（设计 §12.1）；**链形 `[ip, ldap]` ×22（无 tcp/udp 层，raw 自驱）**；16 正例 `expect` 含 `packet_count`；6 负例 `expect` 键集合 = `{expect_error, error_contains, notes}`（含 `notes`，非严格两键，G-LDAP-9）。

**输出契约（pcap/NIC 双输出）**：两路径共用同一 cases JSON 与断言集（`tcp.dstport`、`tcp.flags`、offset 54 frames）；NIC 经 tcpdump 捕获（`nic_capture` 用例级开关）；不设仅单路径可用的断言。

**TSHARK 基线（2026-09-29 自建探针实测）**：本机 tshark 3.6.14 `tshark -G fields` 中 `ldap.*` **159 字段**，`tshark -G decodes` 有 `tcp.port 389 ldap`。**本车道用设计 §3 的 BER 公式在 Python 中复算编码副本**，自建探针 pcap（bindRequest/searchRequest present/searchRequest equality/bindResponse 49/unbind 五消息）经 tshark 解码**零 `_ws.malformed`**。可用字段通道（实测）：

| 字段 | 进制/形态 | 探针实测 |
|---|---|---|
| `ldap.messageID` | 十进制串 | `1`/`2`/`1`/`2`/`3` |
| `ldap.protocolOp` | **十进制枚举号** | `0`(bindReq)/`3`(searchReq)/`1`(bindResp)/`3`/`2`(unbind) |
| `ldap.resultCode` | 十进制串 | `49`（仅 bindResponse 帧） |
| `ldap.scope` | 十进制串 | `0`（两 searchReq 帧） |
| `ldap.filter` | **Filter 分支号** | `7`(present)/`3`(equalityMatch) |
| `ldap.attributes` | **AttributeSelection 项数** | `15`（present 例）/`0`（equality 例） |

`-V` 树形态实证：`LDAPMessage bindRequest(1) "<ROOT>" simple` / `messageID: 1` / `protocolOp: bindRequest (0)` / `version: 3`；`Filter: (objectclass=*)` / `filter: present (7)`；`LDAPMessage bindResponse(1) invalidCredentials` / `resultCode: invalidCredentials (49)`；`Filter: (uid=alice)` / `filter: equalityMatch (3)`；`LDAPMessage unbindRequest(3)`。
> **注意**：枚举**名**（`bindRequest`/`present`/`invalidCredentials`）只在 `-V` 树里出现；`-T fields` 输出的是**枚举号**。

**断言基线**：今日 22 例只用 `packet_count` + `has_handshake` + `terminates` + `has_payload` + `tcp.dstport` + `tcp.flags` + frames；**`ldap.*` field 断言今日零使用**（机读实测 22/22 例 `fields` 数组里无 `ldap.*` 字段）→ **A′ 立项（G-LDAP-19，把已实测可用的 6 个 dissector 字段补起来）**。

**动态字段禁止硬编码**：生成期值（`messageID` 来自配置确定性算法，**可断言**；`seq`/`ack`/`IP ID` 随机，**不可断言**）；`src_port` 由 worker 保底 12345+i（**不可断言**，设计 §12.1）。

**包数约定（实测公式，设计 §5.2）**：`packet_count = 3（握手）+ 5×rounds + [unbind 时 1] + 4（FIN 四包）= 7 + 5×rounds + [unbind]`。负例无 `packet_count`（实测 0 帧）。

**保活/重试/RST 口径**：LDAP 协议层**无 PING 类保活**（`sizeLimit`/`timeLimit` 是服务端约束，非活性探测，设计 §10.1 八项 #6）；**无重试/重连机制**；RST 为框架 tcp 层能力，本协议层不新增断言（A′ 补例 G-LDAP-13 除外）；正例恒 FIN 优雅终止（4 帧）。

**`tcp.flags` 值口径**：`0x002`=SYN、`0x012`=SYN-ACK、`0x010`=ACK、`0x018`=PSH-ACK、`0x011`=FIN-ACK。

## 2. 原子用例索引（22 ID = 16 正 + 6 负，顺序为权威）

| # | ID | 类型 | packet_count | 层内 `ldap` 配置（机读实测） | 覆盖（设计 §） |
|---:|---|---|---:|---|---|
| 1 | `ldap_session_full` | 正 | 13 | `{}` | §3.2/§3.3/§3.7：全会话，六 protocolOp 标签逐帧 |
| 2 | `ldap_ber_long_form_length` | 正 | 13 | `{}` | §3.1/§3.7：恒长形长度前缀专钉（`30 84`/`60 84`） |
| 3 | `ldap_message_id_increment` | 正 | 18 | `{"rounds": 2}` | §3.3：messageID 递增（1,4,2,5,6） |
| 4 | `ldap_bind_anonymous` | 正 | 12 | `{"unbind": false}` | §3.4.1：匿名 bind（name 空串 + simple 空） |
| 5 | `ldap_bind_simple` | 正 | 12 | `{"bind_dn": "cn=admin,dc=test", "bind_password": "s3cret", "unbind": false}` | §3.4.1：simple bind（`80` 标签密码串） |
| 6 | `ldap_bind_version2` | 正 | 12 | `{"version": 2, "unbind": false}` | §3.4.1：version=2 兼容面 |
| 7 | `ldap_scope_single_level` | 正 | 12 | `{"search_scope": 1, "unbind": false}` | §3.5.1：scope=1 |
| 8 | `ldap_scope_whole_subtree` | 正 | 12 | `{"search_scope": 2, "unbind": false}` | §3.5.1：scope=2 |
| 9 | `ldap_filter_equality` | 正 | 12 | `{"filter_type": "equality", "search_filter": "uid", "filter_value": "alice", "unbind": false}` | §3.5.4：equalityMatch `[3]` 隐式标签 |
| 10 | `ldap_result_invalid_credentials` | 正 | 12 | `{"result_code": 49, "unbind": false}` | §3.6：resultCode 49 进响应 |
| 11 | `ldap_rounds_two` | 正 | 17 | `{"rounds": 2, "unbind": false}` | §5.2：rounds=2 多轮（unbind 抑制） |
| 12 | `ldap_attributes_custom` | 正 | 12 | `{"attributes": ["cn", "mail"], "unbind": false}` | §3.5.5：自定义 AttributeSelection |
| 13 | `ldap_unbind_suppressed` | 正 | 12 | `{"unbind": false}` | §5.3 #5：unbind 抑制 |
| 14 | `ldap_composite_multi_round` | 正 | 17 | `{"rounds": 2, "filter_type": "equality", "search_filter": "sAMAccountName", "filter_value": "jdoe", "bind_dn": "CN=svc,DC=corp", "bind_password": "pw", "attributes": ["cn", "member"], "unbind": false}` | §4 场景⑧⑨⑪：四类交织 |
| 15 | `ldap_search_base_dn` | 正 | 12 | `{"search_base_dn": "dc=corp,dc=com", "unbind": false}` | §3.5.1：baseObject 显式 |
| 16 | `ldap_size_time_limit` | 正 | 12 | `{"size_limit": 10, "time_limit": 60, "unbind": false}` | §3.5.1：sizeLimit/timeLimit 两 INTEGER |
| 17 | `ldap_neg_version_invalid` | 负 | —（0 帧） | `{"version": 4}` | §7 N-1 |
| 18 | `ldap_neg_scope_invalid` | 负 | —（0 帧） | `{"search_scope": 3}` | §7 N-2 |
| 19 | `ldap_neg_filter_type_invalid` | 负 | —（0 帧） | `{"filter_type": "substring"}` | §7 N-3 |
| 20 | `ldap_neg_result_code_range` | 负 | —（0 帧） | `{"result_code": 128}` | §7 N-4 |
| 21 | `ldap_neg_size_limit_negative` | 负 | —（0 帧） | `{"size_limit": -1}` | §7 N-5（层 schema 门） |
| 22 | `ldap_neg_message_id_overflow` | 负 | —（0 帧） | `{"message_id_base": 32767, "rounds": 2}` | §7 N-6 |

**T-编号对照**：T-1≡#1、T-2≡#2、T-3≡#3、T-4≡#4、T-5≡#5、T-6≡#6、T-7≡#7、T-8≡#8、T-9≡#9、T-10≡#10、T-11≡#11、T-12≡#12、T-13≡#13、T-14≡#14、T-15≡#15、T-16≡#16、T-负例×5≡#17–#21、T-22≡#22。**无虚号**（与 opcua 旧稿 T4/T8 虚例不同——本协议 22 个 T 号全部对应唯一 JSON ID）。**序号以 cases JSON 顺序为权威**。

## 3. 正例逐项断言契约（最低断言集，实现期可增不可减）

每例均含 `packet_count`；帧位由 §1 公式与设计 §3.7 长度表双向确认。

### 3.1 `ldap_session_full`（13）

层内 `ldap: {}`（全缺省：rounds=1、version=3、匿名 bind、RootDSE 15 属性、present filter、unbind 发）。

- `packet_count=13`、`has_handshake=true`、`terminates=true`、`has_payload=true`。
- `fields`（8 条）：帧1 `tcp.flags=0x002` + `tcp.dstport=389`；帧2 `tcp.flags=0x012`；帧3 `tcp.flags=0x010`；帧4 `tcp.dstport=389`；帧8 `tcp.flags=0x018`；帧9 `tcp.flags=0x018`；帧12 `tcp.flags=0x010`。
- **帧位映射（设计 §5.2 公式）**：帧1-3 握手；帧4 bindReq(up)；帧5 bindResp(down)；帧6 searchReq(up)；帧7 entry(down)；帧8 done(down)；帧9 unbind(up)；帧10 FIN-ACK；帧11 ACK；帧12 FIN-ACK；帧13 ACK。
- `frames`（4 条，offset 54）：帧4 `30 84 00 00 00 10 02 01 01 60`；帧5 `… 02 01 01 61`；帧6 `30 84 00 00 01 58 02 01 02 63`；帧9 `30 84 00 00 00 05 02 01 03 42 00`。
- **六标签证据**：帧4 `60`(bindRequest)/帧5 `61`(bindResponse)/帧6 `63`(searchRequest)/帧8（未钉 hex，设计 §3.3 = `64` entry + `65` done）/帧9 `42`(unbindRequest)。
- **notes 数字勘误（G-LDAP-20）**：存量 notes 写"握手3+bindReq/bindResp+searchReq/entry/done+unbind+挥手4=**12** 包"，而 `packet_count=13`——**12 漏算了 FIN 四帧中的一帧**（正确分解：3 + 5 + 1 + 4 = 13）。**JSON 的 `packet_count=13` 正确**，仅 summary 文案错。P4 须改文案。

### 3.2 `ldap_ber_long_form_length`（13）

层内 `ldap: {}`（与 #1 逐字节同配置）。

- `packet_count=13`；`fields`：帧4 `tcp.dstport=389`。
- `frames`（2 条）：帧4 **offset 63** `60 84 00 00 00 07 02 01 03`；帧6 **offset 54** `30 84 00 00 01 58`。
- **offset 63 的推导**：`54 + 6（外层 SEQUENCE 头）+ 3（`02 01 01` messageID）= 63` = protocolOp 起点（设计 §3.2）。**该断言钉的是"外层恒长形 6 字节头"这一事实**——若实现改用短形（`30 10`），protocolOp 会落到 offset 57，本断言即失败。
- **长形两处证据**：外层 `30 84` + 4B 长度（帧4/帧6 首两字节）；内层 `60 84`（帧4 offset 63）。**内层 content 仅 7 字节却仍用 `0x84` 长形**——设计 §3.1 恒长形对照表第 2 行。
- **notes 数字勘误（G-LDAP-20）**：notes 写"bindReq 内层 len 0x07=version(3)+name(2)+simple(2)；searchReq 外层 len 0x158=344"——**两处均正确**（复算副本实测：opContent 7；外层 content 344）。notes 未写包数，无矛盾。

### 3.3 `ldap_message_id_increment`（18）

层内 `ldap: {"rounds": 2}`（unbind 发）。

- `packet_count=18`、`has_handshake=true`、`terminates=true`；`fields`：帧4 `tcp.dstport=389`。
- `frames`（4 条，全 offset 54）：帧4 `30 84 00 00 00 10 02 01 01 60`（mid=**1** bindReq r1）；帧9 `… 02 01 04 60`（mid=**4** bindReq r2）；帧11 `30 84 00 00 01 58 02 01 05 63`（mid=**5** searchReq r2）；帧14 `30 84 00 00 00 05 02 01 06 42 00`（mid=**6** unbind）。
- **messageID 分配证据（设计 §3.3 公式 `base+3r+k`）**：r1 → bind 1 / search 2 /（无 unbind）；r2 → bind 4 / search 5；unbind = `base+3(rounds-1)+2` = 1+3+2 = **6**。帧位：3 握手 + r1 五帧（4-8）+ r2 五帧（9-13）+ unbind（14）+ FIN（15-18）= **18** ✓。
- **notes 数字勘误（G-LDAP-20）**：notes 写"3 握手+2 轮×5 消息+unbind+4 挥手=**17**"——**17 错，应为 18**（`packet_count=18` 正确；3+10+1+4 = 18）。同条 notes 的 messageID 钉（帧4=1/帧9=4/帧11=5/帧14=6）**全部正确**。

### 3.4 `ldap_bind_anonymous`（12）

层内 `ldap: {"unbind": false}`（rounds=1、匿名 bind、RootDSE 15 属性）。

- `packet_count=12`；`fields`：帧4 `tcp.flags=0x018`。
- **匿名证据（设计 §3.4.1）**：`bind_dn`/`bind_password` 双缺省 → opContent = `02 01 03 04 00 80 00`（7B），整包 22B。**帧4 的 hex 未钉**——A′ 可补（G-LDAP-19）。
- **notes 数字勘误（G-LDAP-20）**：notes 写"unbind=false（**11** 包）"——**11 错，应为 12**（`packet_count=12` 正确）。notes 的实质说明（匿名面 = bind_dn/bind_password 缺省空）**正确**。

### 3.5 `ldap_bind_simple`（12）

层内 `ldap: {"bind_dn": "cn=admin,dc=test", "bind_password": "s3cret", "unbind": false}`。

- `packet_count=12`；`fields`：帧4 `tcp.flags=0x018`。
- **simple 认证证据（设计 §3.4.1）**：opContent = `02 01 03`（version）+ `04 11` + 17 字节 DN + `80 06` + 6 字节 `s3cret` = 3+19+8 = **29B**，整包 **44B**（复算副本实测）。`0x80` 是 `simple [0]` 上下文标签（RFC 4511 §4.2.1）。
- **notes 数字勘误（G-LDAP-20）**：notes 写"unbind=false（**11** 包）"——同 #4，**11 错应为 12**。

### 3.6 `ldap_bind_version2`（12）

层内 `ldap: {"version": 2, "unbind": false}`。

- `packet_count=12`；`fields`：帧4 `tcp.flags=0x018`。
- **version 字节证据（设计 §3.4.1）**：`berInt(2)` = `02 01 02`（缺省 3 由 #1 承接，其帧4 第 9-11 字节为 `02 01 03`）。
- **notes**：无数字，仅"RFC 4511 §4.2.1 version2 兼容面"。**正确**。

### 3.7 `ldap_scope_single_level`（12）

层内 `ldap: {"search_scope": 1, "unbind": false}`。

- `packet_count=12`；`fields`：**帧6** `tcp.flags=0x018`（帧6 = searchRequest）。
- **scope 字节证据（设计 §3.5.1）**：`berEnum(1)` = `0a 01 01` 位于 opContent offset 2（整包 offset 54+6+3+2 = 65）。
- **notes**：无数字，仅"RFC 4511 §4.5.1.2 枚举 1"。**正确**。

### 3.8 `ldap_scope_whole_subtree`（12）

层内 `ldap: {"search_scope": 2, "unbind": false}`。

- `packet_count=12`；`fields`：帧6 `tcp.flags=0x018`。
- **scope 字节证据**：`berEnum(2)` = `0a 01 02`。**缺省 0 由 #1 承接**（notes 明写）。
- **notes**：无数字。**正确**。

### 3.9 `ldap_filter_equality`（12）

层内 `ldap: {"filter_type": "equality", "search_filter": "uid", "filter_value": "alice", "unbind": false}`。

- `packet_count=12`；`fields`：帧6 `tcp.flags=0x018`。
- **equality 编码证据（设计 §3.5.4）**：filter = `a3 84 00 00 00 10 04 03 75 69 64 04 05 61 6c 69 63 65`（18B，复算副本实测）——**`a3` 是 constructed [3]（隐式标签的 AttributeValueAssertion），内容直接是两个 OCTET STRING，无嵌套 SEQUENCE**。
- **整包长度**：opContent = 17 + 18 + 6 + 0（`attributes` 缺省被覆盖？否——**本例未写 `attributes`，故仍是 15 个 RootDSE 属性**）= 17+18+6+299 = **340**，整包 **355**（复算实测 `30 84 00 00 01 5d`）。**该值今日无断言**（A′ 可补，G-LDAP-19）。
- **notes**：无数字，仅"equalityMatch [3]：attr OCTET STRING + assertionValue 直接内联（无嵌套 SEQUENCE）"。**正确**。

### 3.10 `ldap_result_invalid_credentials`（12）

层内 `ldap: {"result_code": 49, "unbind": false}`。

- `packet_count=12`；`fields`：**帧5** `tcp.flags=0x018`（帧5 = bindResponse）。
- **resultCode 证据（设计 §3.6）**：bindResponse 与 searchResDone 的 LDAPResult 首字段 = `berEnum(49)` = `0a 01 31`。**帧5 的 hex 未钉**——A′ 可补（G-LDAP-19）。
- **`result_code` 同时影响 bindResponse（帧5）与 searchResDone（帧8）**：两处都用 `ldapResult(cfg)`（`ldap.go:186-191`）。**今日只断帧5 的 flags，不断 resultCode 字节**。
- **诚实声明（设计 §5.1 非法转移 #2）**：本例**固化了"bind 失败（resultCode=49）后仍继续发 search"**这一与 RFC 4511 §4.2.2 建议（客户端 SHOULD 终止会话）不符的行为。notes 只写"RFC 4511 §4.1.9 ENUMERATED 49=invalidCredentials"，**未声称符合 §4.2.2**——本用例**不断言状态机合规**。
- **notes**：无数字。**正确**。

### 3.11 `ldap_rounds_two`（17）

层内 `ldap: {"rounds": 2, "unbind": false}`。

- `packet_count=17`、`has_handshake=true`、`terminates=true`；`fields`：帧4 `tcp.flags=0x018`、帧9 `tcp.flags=0x018`（**两轮各自的 bindReq**）。
- **包数证据**：3 + 2×5 + 0 + 4 = **17** ✓。
- **notes**：写"3 握手+2×5+4 挥手=**16**"——**16 错，应为 17**（`packet_count=17` 正确；3+10+4 = 17）。同条 notes 的"messageID 1/2 与 4/5 两轮续编，unbind 抑制"**正确**（与 #3 的 r1/r2 分配一致）。

### 3.12 `ldap_attributes_custom`（12）

层内 `ldap: {"attributes": ["cn", "mail"], "unbind": false}`。

- `packet_count=12`；`fields`：帧6 `tcp.flags=0x018`。
- **AttributeSelection 证据（设计 §3.5.5）**：2 个属性 → `30 84 00 00 00 0a 04 02 63 6e 04 04 6d 61 69 6c`（content 10B = (2+2)+(2+4)）；opContent = 17+13+6+10 = **46**，整包 **61**（复算实测 `30 84 00 00 00 37`）。
- **entry 同步缩短**：`searchResEntry` 的 PartialAttributeList 也按同列表生成 → 2 个 partial，每个 `16+2×len` → entry opContent = 2+6+ (16+4)+(16+8) = **52**，整包 **67**。
- **notes**：写"消息缩短，长形→短形边界面"——**措辞不准确（G-LDAP-21）**：本实现 constructed 值**恒用长形**（`berWrap`），`attributes: ["cn","mail"]` 下 searchRequest **外层仍是 `30 84` 长形**（复算实测首两字节 `30 84`）。**不存在"长形→短形"切换**——真正变化的是**长度数值**（344 → 37），不是**长度形态**。P4 须改文案。
- **空属性不可表达（G-LDAP-3）**：`attributes: []` 经 `parseStringList` 归 nil，与键缺席同 → 回退 15 个 RootDSE 属性。**本例不断言空属性面**。

### 3.13 `ldap_unbind_suppressed`（12）

层内 `ldap: {"unbind": false}`（与 #4 逐字节同配置）。

- `packet_count=12`、`terminates=true`；`fields`：帧8 `tcp.flags=0x018`（末个 done）、帧9 `tcp.flags=0x011`（**FIN-ACK，挥手首帧**）。
- **unbind 抑制证据**：`unbind=false` → 不发 `42` 帧，帧8（done）后**径直**帧9 FIN-ACK。
- **与 #4 的区分（§8.3 覆盖论证）**：两例 `spec_json` 逐字节相同，但**断言面互补**——#4 钉 bind 面的 `tcp.flags=0x018`（帧4），#13 钉 **unbind 抑制后的帧位**（帧8 是 done 而非 unbind、帧9 是 FIN-ACK）。**删除任一例将失去其独有证据**（§7 不可再分判定标准）。
- **notes 数字勘误（G-LDAP-20）**：notes 写"unbind 指针三态 false=抑制（T-1 缺省 true 对面）；包9=FIN-ACK 挥手首帧"——**无包数数字**，无矛盾；"unbind=false（**11** 包）"是 **summary** 里的（见 §8.2）。summary 写"末 done 后径直挥手（**11** 包）"——**11 错应为 12**。

### 3.14 `ldap_composite_multi_round`（17）

层内 `ldap`：rounds=2 + equality filter（`sAMAccountName=jdoe`）+ 非匿名 bind（`CN=svc,DC=corp`/`pw`）+ 自定义属性 `["cn","member"]` + unbind 抑制。

- `packet_count=17`、`has_handshake=true`、`terminates=true`；`fields`：帧4 `tcp.flags=0x018`、帧9 `tcp.flags=0x018`（两轮 bindReq）。
- **包数证据**：3 + 2×5 + 0 + 4 = **17** ✓。
- **四类交织证据（设计 §4 场景⑧⑨⑪）**：① rounds=2 → 帧4/9 两 bindReq；② equality → 每轮 searchReq 的 filter 是 `a3` 分支；③ 非匿名 bind → 每轮 bindReq 含 DN+密码；④ 自定义 2 属性 → 每轮 searchReq/entry 的 AttributeSelection 为 2 项。
- **notes 数字勘误（G-LDAP-20）**：**summary** 写"≥3 类交织；**16** 包"——**16 错应为 17**（`packet_count=17` 正确）。notes 写"多轮+equality+simple 认证+自定义属性四类交织；AD 现网服务账号查询形"——**无数字，正确**。

### 3.15 `ldap_search_base_dn`（12）

层内 `ldap: {"search_base_dn": "dc=corp,dc=com", "unbind": false}`。

- `packet_count=12`；`fields`：帧6 `tcp.flags=0x018`。
- **baseObject 证据（设计 §3.5.1）**：searchRequest 首字段 = `04 0e` + `dc=corp,dc=com`（14 字节）；**`searchResEntry` 的 objectName 同步该值**（`ldap.go:272`，同一 `cfg.SearchBaseDN`）。
- **长度影响**：opContent = 16（baseObject）+ 15 + 13 + 299 = **343**，整包 **358**（比缺省 350 多 8 = 14−6… 精确：baseObject 16B vs 缺省 2B，差 14；故 350+14 = 364？——复算：缺省 opContent 335，本例 = 335 − 2 + 16 = 349，整包 364）。**该值今日无断言**（A′ 可补）。
- **notes**：写"RFC 4511 §4.5.1.1 baseObject；entry 的 objectName 同步该值"——**无数字，正确**。

### 3.16 `ldap_size_time_limit`（12）

层内 `ldap: {"size_limit": 10, "time_limit": 60, "unbind": false}`。

- `packet_count=12`；`fields`：帧6 `tcp.flags=0x018`。
- **两 INTEGER 证据（设计 §3.5.1）**：sizeLimit = `berInt(10)` = `02 01 0a`（opContent offset 8）；timeLimit = `berInt(60)` = `02 01 3c`（offset 11）。**两者都是 3 字节**（值 ≤127），故整包长度与缺省一致（350）。
- **notes**：写"RFC 4511 §4.5.1.3/4；参考 pcap timeLimit 120 同族面"——**无数字，正确**。

**正例总则**：多轮、多属性、自定义 filter、非缺省 baseDN 均为正例形态，只有配置/范围错误进入负例。

## 4. 负例契约

负例必须在 `Validate` 阶段失败并传播为 task error，不得产生成功 PCAP、`completed/0 packet` 或只剩 TCP 外壳的假成功（**6 例均零包**）。锚词与设计 §7 表一一对应、同序：

| # | ID | 故障输入（机读实测） | JSON `error_contains` | 代码文案（逐字） | 代码行 |
|---:|---|---|---|---|---|
| N-1 | `ldap_neg_version_invalid` | `{"version": 4}` | `invalid version` | `ldap: invalid version 4 (allowed: 2, 3)` | `ldap.go:94-96` |
| N-2 | `ldap_neg_scope_invalid` | `{"search_scope": 3}` | `invalid scope` | `ldap: invalid scope 3 (allowed: 0, 1, 2)` | `ldap.go:97-99` |
| N-3 | `ldap_neg_filter_type_invalid` | `{"filter_type": "substring"}` | `invalid filter type` | `ldap: invalid filter type "substring" (allowed: present, equality)` | `ldap.go:100-102` |
| N-4 | `ldap_neg_result_code_range` | `{"result_code": 128}` | `out of ENUMERATED range` | `ldap: result_code 128 out of ENUMERATED range (0-127)` | `ldap.go:103-105` |
| N-5 | `ldap_neg_size_limit_negative` | `{"size_limit": -1}` | `size_limit` | **`layers: layer "ldap" field "size_limit" = -1 invalid: out of range [0,2147483647]`** | **`complete.go:325`** |
| N-6 | `ldap_neg_message_id_overflow` | `{"message_id_base": 32767, "rounds": 2}` | `exceeds 0x7FFF` | `ldap: message id 32770 exceeds 0x7FFF` | `ldap.go:120-122` |

**锚词口径**：`error_contains` 是**子串**判定；6 例全部命中（N-1…N-4/N-6 命中 `ldap: ` 前缀文案；N-5 命中层 schema 文案）。

**N-5 的特殊性（G-LDAP-7，confirmed finding）**：`size_limit: -1` **不由 ldap validator 拒绝**。层链路径上 registry schema 声明 `"size_limit": {Type:"int", Min:0, Max:2147483647}`（`registry.go:1899`），`ValidateLayers → ValidateLayerConfig`（`complete.go:325`）先于 translate 执行，负值在此判死。`Planner.Validate` 的 `ldap.go:106-108` 分支（锚词 `ldap: size_limit must be >= 0`）**在层链路径不可达**。**即：`error_contains: "size_limit"` 同时命中两个来源**——层链路径 = `complete.go:325`（今日实际），引擎直调路径 = `ldap.go:107`。**本契约不声称 ldap validator 覆盖该输入**。

**N-6 的数值**：`message_id_base=32767, rounds=2` → `base+3×(rounds-1)+2 = 32767+3+2 = 32772`。**JSON 锚词 `exceeds 0x7FFF` 正确**；设计 §7 表的公式与之一致。

**负例原子性**：每例单一故障注入；单次执行不得混注。

**expect 键形状注**：存量 6 负例 `expect` = `{expect_error, error_contains, notes}`（含 `notes`），与 92-moxa 范式的严格两键不同——P4 收窄时删 `notes`（G-LDAP-9）。

**未入用例的拒绝分支（A′ 立项，不得冒充已覆盖）**：`size_limit < 0`（validator 面，不可达）/ `time_limit < 0`（`ldap.go:109-111`，不可达）/ `LDAP == nil`（`:89-91`，translate 恒产非 nil）/ `SrcIP`/`DstIP` 非法（`:79-88`，`validateSpecBase` 先验）/ `berInt` 的 `00` 前置分支（`:141-143`，`MaxMessageID` 保证不可达）。

## 5. 覆盖与对账

### 5.1 三源回指行

**三源** = RFC 4511 原文（设计 §10，本机拉取 3811 行逐节引用）+ D-LDAP-1（设计 §11）+ tshark 3.6.14 字段表与**自建探针 pcap 实测**（设计 §1.3，六字段逐条实证）→ 22 ID（本契约 §2）。第三源"已确认现网行为"当前 = **抓包级部分到位**（BER 编码形态经 tshark 实证；参考 pcap 的编码习惯被镜像，但**参考 pcap 文件本身不在本仓**、真实服务器线字节未抓）→ G-LDAP-14（按 §5.5 不写死进实现）。

**22 ID 逐项回指（§9.5 要求）**：#1←设计 §3.2/§3.3；#2←§3.1；#3←§3.3；#4←§3.4.1；#5←§3.4.1；#6←§3.4.1；#7←§3.5.1；#8←§3.5.1；#9←§3.5.4；#10←§3.6；#11←§5.2；#12←§3.5.5；#13←§5.3；#14←§4；#15←§3.5.1；#16←§3.5.1；#17←§7 N-1；#18←§7 N-2；#19←§7 N-3；#20←§7 N-4；#21←§7 N-5；#22←§7 N-6。

### 5.2 对账两行 + 清单出处声明

- **清单出处声明**：本清单来源 = **RFC 4511 公开语义（原文逐节）+ 本仓落码反推 + tshark 3.6.14 字段表与自建探针 pcap 实测**，**非纯规范反推**（参考 pcap 文件不在本仓 → G-LDAP-14）。
- **对账两行**：**要求逻辑点总数 = 107**（八项 8 行 + 矩阵 33 格 + 变体 48 行 + 商业映射 18 行）。**逐表重数（权威，逐行/逐格清点，每点按主分类计一次）**：八项 8 行 = 覆 **5** + 立项 **3**（G-LDAP-11/G-LDAP-6/A′ 6 条）+ 不适用 **0**；矩阵 33 格 = 覆 **19**（T1 列 10 + T2 列 9）+ A′ 立项 **9**（T3 列 9）+ 不适用 **5**（1+2+2）；变体 48 行 = 覆 **36** + A′ 立项 **11**（8 纯 + 3 复合行）+ 不可表达 **1**（G-LDAP-3）；商业 18 行 = 覆 **12** + 不适用 **6**。
  **合计**：覆盖 = 5 + 19 + 36 + 12 = **72**；不适用 = 0 + 5 + 1 + 6 = **12**；开放立项 = 3 + 9 + 11 + 0 = **23**。**72 + 12 + 23 = 107** ✓
  **粒度声明**：行/格粒度每点 1 计（**无重复计数**——变体表的 3 个"覆 + 补面"复合行按**待补面**计立项，其已覆面在行内注明）；G-LDAP-1…G-LDAP-21 不折进 107。**反查全绿 ≠ 覆盖全**（§9.52 原文）。逐表重数见设计 §10.1（8 = 覆 5 + 立项 3）/§10.2（33 = 覆 19 + A′ 9 + 不适用 5）/§10.3（48 = 覆 36 + 立项 11 + 不可表达 1）/§10.4（18 = 覆 12 + 不适用 6）。
- **门3 抽查候选**：最复杂用例 = **#14 `ldap_composite_multi_round`**（17 帧：握手 3 + 2 轮 × (bind 对 + search 三件) + FIN 4；交织维度 = 轮次(2)×消息类型(3)×方向(2)×bind 形态(1)×filter 分支(1)×属性列表(2)）；**建议门3 抽 #14 + #3**（`ldap_message_id_increment` 补 messageID 分配面）。

### 5.3 T-编号与 ID 对照（设计 §9 全表摘要）

`ldap_session_full`≡T-1；`ldap_ber_long_form_length`≡T-2；`ldap_message_id_increment`≡T-3；`ldap_bind_anonymous`≡T-4；`ldap_bind_simple`≡T-5；`ldap_bind_version2`≡T-6；`ldap_scope_single_level`≡T-7；`ldap_scope_whole_subtree`≡T-8；`ldap_filter_equality`≡T-9；`ldap_result_invalid_credentials`≡T-10；`ldap_rounds_two`≡T-11；`ldap_attributes_custom`≡T-12；`ldap_unbind_suppressed`≡T-13；`ldap_composite_multi_round`≡T-14；`ldap_search_base_dn`≡T-15；`ldap_size_time_limit`≡T-16；`ldap_neg_version_invalid`≡T-负例；`ldap_neg_scope_invalid`≡T-负例；`ldap_neg_filter_type_invalid`≡T-负例；`ldap_neg_result_code_range`≡T-负例；`ldap_neg_size_limit_negative`≡T-负例；`ldap_neg_message_id_overflow`≡T-22。**22/22 一一对应，无虚号**。

## 6. P3 固定动作（CORE_MEMORY 管线：§3.15 三项 + A′/B′ 两分类 + 3.14 豁免）

### 6.1 §3.15 三项逐项一例或立项

| # | 三项 | 本协议对照 | 用例/立项 |
|---:|---|---|---|
| ① | 同连接/同流内的多轮操作 | 单 TCP 连接内 `rounds` 轮 bind/search（#3 两轮、#11 两轮、#14 两轮交织） | **已覆 #3/#11/#14** |
| ② | 非正常结束 | 正常 FIN 四帧全正例；应用层正常终止 = unbind（#1/#3）或抑制后 FIN（#4–#16）；传输异常 = RST | 已覆（unbind 两态 #1/#13 + FIN 全正例）；**RST A′ 立项**（G-LDAP-13，本层零断言） |
| ③ | 长保活 | **LDAP 协议层无保活心跳**——`sizeLimit`/`timeLimit` 是**服务端约束**（RFC 4511 §4.5.1.4/§4.5.1.5），不是活性探测；LDAP 也无 PING/keepalive 消息 | **显式不适用 + 登记**：§3.15③ 按"协议不适用"处理（G-LDAP-12），**不硬凑用例**；多轮面由 ① 承接 |

无空项：① 有已覆例；② 有已覆例 + 1 条 A′ 立项；③ 显式不适用 + 立项登记（理由 = 规范无此机制）。

### 6.2 A′/B′ 两分类表

**A′（P4 接线）**：

| 类 | 内容 | 落点 |
|---|---|---|
| field 断言面 | 收编 tshark `ldap.*` 字段（`messageID`/`protocolOp`/`resultCode`/`scope`/`filter`/`attributes`）——今日零使用 | G-LDAP-19 |
| 地址族面 | IPv6 独立用例（`EtherTypeFor` 支持，offset 74） | G-LDAP-5 |
| 边界面 | BER 短形↔长形 127/128 边界；`mid ≥ 128` 4 字节 INTEGER；`result_code=127` | G-LDAP-10 |
| 长度上界面 | `attributes` 100×20（2251B，仅单测）；`bind_dn` 长 ≥128（primitive 长形） | G-LDAP-10 |
| 分段面 | MSS 跨分段（仅单测 `TestPlan_MSSSegmentation`） | G-LDAP-10 |
| 拒绝分支面 | `time_limit < 0`（同 N-5 口径）；`filter_type: "present"` 显式串；equality + 空 value | G-LDAP-8、设计 §10.3 #28/#33 |
| 判死负例面 | `{"layers":[…],"ldap":{}}` presence 判死（**本协议门已合，可建**，与 opcua 相反） | G-LDAP-17 |
| 非正常结束 | `tcp.rst` 补例 | G-LDAP-13（② 的 A′） |
| 地址族混写 | 异族混写拒绝 | 设计 §10.3 #48 |
| 动态面 | `search_filter`/`filter_value` 逐流变（现网多用户批量查询真实场景） | G-LDAP-18 |

**B′（框架面）**：顶层未知游离键通用门（`{layers:[…], bogus:1}` 今日不判死，G-LDAP-15，等框架级 unknown-key 白名单，**禁加单协议黑名单分支**）/ 业务字段动态（G-LDAP-18，allowlist 无 `ldap` 行）/ 负例 `notes` 键收窄（G-LDAP-9）。进设计 §14。

### 6.3 3.14 豁免边界审计

**有长连接载体（TCP，生成器自建）→ `sessions[]` 不豁免**（设计 §12.3 会话表 s1）。**本协议无 `sessions[]` 结构**——`rounds` 是**同连接内的多轮**（层内结构选择器，非 `sessions[]` 数组），**形态差异已声明**（设计 §5.4/§12.3）。多流并发由策略级 `flow_control {"flows": N}` 承载（本版 22 例未用，全单流）。**单包多载荷** = **不适用**（LDAP 每 LDAPMessage 一个 protocolOp，无多 question/多 RR 类形态，如实声明）。

## 7. 实现后执行建议

1. **P4 顺序**：①先改 4 条错文案（G-LDAP-20，见 §8.2）；②补 A′ field 断言（收编 `ldap.*` 6 字段）；③补 A′ 边界/地址族/拒绝分支例；④裁定 G-LDAP-3（`attributes:[]`）与 G-LDAP-7（N-5 锚词来源）；⑤删 6 负例的 `notes`（G-LDAP-9）；⑥全量复跑。**本协议无 §1 迁移步骤**（顶层零残留）。
2. **实测顺序**：先 #1（全会话 13 帧基线 + 六标签帧位），再 #2（恒长形 offset 63 专钉），再 #3（messageID 分配 1/4/2/5/6），再 #12（属性 2 项 → 整包 61），最后 #11/#14（两轮 17 帧）。
3. 二进制与 HEAD 同代确认（门2③：`find trafficgen -name '*.go' -newer <server-binary>` 无输出）；门2② 全量（`CASE_PROTO=ldap` 全量不是增量）；门2④ 反查绿后进 P6。
4. **RFC 4511 条款号引用纪律**：本契约所有 §x.y.z 均来自本机拉取的原文（设计 §3 各表逐节标注），**不臆造**；若发现与原文不符须改文档（G-LDAP-14 纪律）。

## 8. 存量审计（22 例逐条去向）

### 8.1 存量实测面（2026-09-29）

`cases/ldap.json` **22 例**：16 正带 `packet_count`（13/13/18/12/12/12/12/12/12/12/17/12/12/17/12/12）；**包数公式 `7+5×rounds+[unbind]` 与 16/16 一致**（机读实测）；6 负 `expect` 键集合 `{expect_error,error_contains,notes}`，零包；**22/22 顶层键仅 `{layers}`（零残留）**；链形 `[ip,ldap]` ×22；10 条 frame 断言（4+2+4 分布于 #1/#2/#3）逐条与设计 §3.7 长度表复算一致（**全 OK**）；层内 `ldap` 配置已带 registry Fields 15 键的子集。

### 8.2 现状矛盾点（P4 前诚实登记）

1. **summary/notes 包数文案错 6 处（G-LDAP-20）**——`packet_count` 值**全部正确**，仅文案数字错：

| ID | 文案位置 | 存量原文数字 | 正确值 | 分解 |
|---|---|---:|---:|---|
| `ldap_session_full` | summary `挥手4=12 包` | 12 | **13** | 3+5+1+4 |
| `ldap_bind_anonymous` | notes `11 包` | 11 | **12** | 3+5+0+4 |
| `ldap_message_id_increment` | notes `挥手=17`（**无"包"字**） | 17 | **18** | 3+10+1+4 |
| `ldap_rounds_two` | notes `挥手=16`（**无"包"字**） | 16 | **17** | 3+10+0+4 |
| `ldap_unbind_suppressed` | summary `11 包` | 11 | **12** | 3+5+0+4 |
| `ldap_composite_multi_round` | summary `16 包` | 16 | **17** | 3+10+0+4 |

2. **`ldap_attributes_custom` 的 notes 措辞不准（G-LDAP-21）**：原文"消息缩短，长形→短形边界面"——本实现 constructed 值**恒长形**，`attributes: ["cn","mail"]` 下 searchRequest 外层**仍是 `30 84`**（复算实测）。变化的是**长度数值**（344 → 37），**不是长度形态**。P4 须改文案。
3. **`ldap_filter_equality` 的 notes 未提长度**：本例 opContent = 340、整包 355（复算实测），**今日无断言**（A′ 可补，G-LDAP-19）。
4. **`ldap_session_full` 与 `ldap_ber_long_form_length` 同配置**（`{}`）——**非重复用例**：前者钉六 protocolOp 标签的帧位与 flags，后者钉 **offset 63**（外层恒长形 6 字节头）这一独立事实（§3.2/§8.3）。
5. **`ldap_bind_anonymous` 与 `ldap_unbind_suppressed` 同配置**（`{"unbind": false}`）——**非重复用例**：前者钉 bind 面（帧4 PSH-ACK），后者钉 unbind 抑制后的帧位（帧8 = done、帧9 = FIN-ACK）（§3.13/§8.3）。
6. **`attributes: []` 不可表达（G-LDAP-3）**：`parseStringList` 空数组归 nil，与键缺席同 → 回退 15 个 RootDSE 属性；`ldap.go:206-207` 注释声称的能力经层链 JSON 路径**不可达**。
7. **N-5 锚词来源非 ldap validator（G-LDAP-7）**：`size_limit: -1` 由 `complete.go:325`（registry `Min:0`）拦，`ldap.go:106-108` 分支**不可达**。
8. **`ldap.*` field 断言零使用**：22/22 例 `fields` 数组只含 `tcp.*`；6 个已实测可用的 ldap dissector 字段**未被收编**（A′ G-LDAP-19）。
9. **存量未覆盖**：IPv6、BER 127/128 边界、`mid ≥ 128` 4 字节、`result_code=127`、`attributes` 100 项、MSS 分段、`bind_dn` 长 ≥128、`time_limit` 负、`filter_type: "present"` 显式、equality 空 value、异族混写、presence 判死负例、RST **今日零用例**（A′ 补，§6.2）。
10. **结果文档过期（G-LDAP-1）**：tracked 产物 `trafficgen/docs/protocol-pcap-test/ldap.md` 写 `Cases: 22 — pass 22, fail 0, error 0`，末次提交 `064f9b6`（**2026-09-20**），`docs/protocol-pcap-test/ldap/` **0 个 pcap**（目录不存在）。故该 22/22 **未经今日复跑证实，不得作为"今日已复跑"依据**。**ldap 特殊性（须写清，不得夸大）**：`064f9b6`（2026-09-20）**晚于**判死提交 `0417be5`（2026-09-13）——**不存在** opcua 那种"末次提交早于判死提交"形态；22/22 顶层键仅 `{layers}`（§1），故 22 例**今日仍应可跑**；本车道未跑该套件，故不以任何形式引用该产物。归属**代码阶段**（P5 重跑套件后重生成该产物）。

### 8.3 逐条去向表（22 行）

| 存量 id | T-编号 | 去向 | 改写动作（P4） |
|---|---|---|---|
| `ldap_session_full` | T-1 | **保留** | 改 summary 包数 12→13；可补 `ldap.protocolOp` 六标签断言 |
| `ldap_ber_long_form_length` | T-2 | **保留** | 形状已合规；可补 `ldap.messageID` 断言 |
| `ldap_message_id_increment` | T-3 | **保留** | 改 notes 包数 17→18；可补 4 处 `ldap.messageID` 断言 |
| `ldap_bind_anonymous` | T-4 | **保留** | 改 notes 包数 11→12；可补帧4 hex（`04 00 80 00` 匿名面） |
| `ldap_bind_simple` | T-5 | **保留** | 改 notes 包数 11→12；可补帧4 hex（`80 06` + 密码） |
| `ldap_bind_version2` | T-6 | **保留** | 可补帧4 hex（`02 01 02` version 字节） |
| `ldap_scope_single_level` | T-7 | **保留** | 可补 `ldap.scope=1` 断言 |
| `ldap_scope_whole_subtree` | T-8 | **保留** | 可补 `ldap.scope=2` 断言 |
| `ldap_filter_equality` | T-9 | **保留** | 可补 `ldap.filter=3` + 帧6 hex（`a3 84 …`） |
| `ldap_result_invalid_credentials` | T-10 | **保留** | 可补 `ldap.resultCode=49` 断言；**断言口径收窄说明**（不断言状态机合规，§3.10） |
| `ldap_rounds_two` | T-11 | **保留** | 改 notes 包数 16→17 |
| `ldap_attributes_custom` | T-12 | **改写** | 改 notes 措辞（删"长形→短形"，改"长度数值缩短"）；可补 `ldap.attributes=2` |
| `ldap_unbind_suppressed` | T-13 | **保留** | 改 summary 包数 11→12 |
| `ldap_composite_multi_round` | T-14 | **保留** | 改 summary 包数 16→17；可补 `ldap.attributes=2` |
| `ldap_search_base_dn` | T-15 | **保留** | 可补帧6 baseObject hex |
| `ldap_size_time_limit` | T-16 | **保留** | 可补帧6 两 INTEGER hex（`02 01 0a`/`02 01 3c`） |
| `ldap_neg_version_invalid` | T-负例 | **保留** | 删 `notes`（G-LDAP-9） |
| `ldap_neg_scope_invalid` | T-负例 | **保留** | 删 `notes` |
| `ldap_neg_filter_type_invalid` | T-负例 | **保留** | 删 `notes` |
| `ldap_neg_result_code_range` | T-负例 | **保留** | 删 `notes` |
| `ldap_neg_size_limit_negative` | T-负例 | **保留** | 删 `notes`；**登记锚词来源为 `complete.go:325`**（G-LDAP-7） |
| `ldap_neg_message_id_overflow` | T-22 | **保留** | 删 `notes` |

**统计**：**保留 21 + 改写 1 + 作废 0 + 等价覆盖 0**。改写仅 `ldap_attributes_custom`（措辞纠正）；5 条包数文案错属"保留 + 文案修复"（`packet_count` 本身正确，非用例改写）。**本协议存量 22/22 顶层零残留**（与 opcua/ftp/jt808 等共 27 个协议同为纯层链形，**非全仓唯一**；见设计 §12.1）。

## 9. 附：覆盖反查门建议断言行（供主线程合后登记；本车道不碰 `coverage_gate.py`）

**现状说明**：`coverage_gate.py` **已有 `check_ldap`**（`coverage_gate.py:3744`，43 项，**本车道实测 43/43 通过 —— 绿**）。下列为**建议增补**行（现有 43 项已覆盖 22 ID 点名 / 15 键 / 6 锚词三面；增补针对本版新增的机读面）：

| # | 建议断言 | 依据 |
|---:|---|---|
| 1 | `len(cases['ldap']) == 22` 且 ID 集合 = §2 二十二项，顺序一致 | 本契约 §2 |
| 2 | 22/22 例 `spec_json` 顶层键 == `{layers}`（**本协议零游离键**） | 本契约 §1；设计 §12.1 |
| 3 | 22/22 例链形 == `[ip, ldap]`（**无 tcp/udp 层**，raw 自驱族特征） | 本契约 §1；设计 §2 |
| 4 | 16 正例 `packet_count == 7 + 5×rounds + (1 if unbind 未抑制 else 0)` | 设计 §5.2 公式 |
| 5 | 6 负例 `expect` 键 == `{expect_error, error_contains}`（P4 删 `notes` 后） | 本契约 §4 |
| 6 | 负例 `error_contains` ∈ 代码锚词集 `{"invalid version","invalid scope","invalid filter type","out of ENUMERATED range","size_limit","exceeds 0x7FFF"}` | 设计 §7 |
| 7 | 非负例顶层键计数 == 0（**今日已成立**） | 设计 §12.1 |
| 8 | 每正例至少一条断言落在 `tcp.flags` 或 `tcp.dstport` 或 frames | 本契约 §3 |
| 9 | 每条 frame 断言的 `offset` ∈ `{54, 63}`（IPv4：54 = 载荷起点；63 = 54+6+3 = protocolOp 起点） | 设计 §3.2 |
| 10 | 文案包数一致性：summary/notes 内出现的"N 包"数字若存在，须 == `packet_count`（**今日 6 处红**，G-LDAP-20——机读正则 `(\d+)\s*包` **只命中 4 处**；`ldap_message_id_increment` 的 `挥手=17` 与 `ldap_rounds_two` 的 `挥手=16` **无"包"字，正则判不到**，故建议登记"**6 处须人读核对**"；该缺口本身即"正则扫不全"的实例）。建议登记为**已知红**，P4 修复后转绿 | 本契约 §8.2 |

**另注意**：`docs/protocol-pcap-test/ldap.md` 的 22/22 pass 是**过期产物**（G-LDAP-1，末次提交 `064f9b6` 2026-09-20；`docs/protocol-pcap-test/ldap/` 0 个 pcap），**不得作为"今日已复跑"依据**（口径与 pcep G-PCEP-11 / opcua G-OPCUA-10 一致）。**但 ldap 22/22 例顶层键仅 `{layers}`，今日仍应可跑**——该提醒**仅限**"数字未经今日复跑证实 + 无 pcap 留档"，**不得读成"套件不可跑"**。

**建议断言 #10 的诚实标注**：该行**今日为红**（6 处文案数字与 `packet_count` 不符，§8.2 第 1 条）。**本车道不申报"今日已过"**——如实标红，P4 修文案后转绿。

## 10. 修订记录

- v1.0.0（2026-09-29）：批次二 as-built 文档轨 #111。**承同族记忆**（BER 恒长形 / srcport 12345 陷阱 / raw 自驱五件套）落到 §1/§3/§8。三源 = RFC 4511 原文 + D-LDAP-1 + **自建探针 pcap 实测**（六字段逐条实证，零 malformed）。**形状基线机读实测**（§1，顶层零残留）；**包数公式 `7+5×rounds+[unbind]` 与 16/16 一致**；10 条 frame 断言逐条与设计 §3.7 复算一致（全 OK）；P3 固定动作（§6）；执行建议（§7）；存量审计（§8，21 保留 + 1 改写 + 0 作废）；覆盖反查门建议断言行（§9，**含 1 条今日为红的诚实标注**）。**新增缺口**：G-LDAP-19（`ldap.*` field 断言零使用）/ G-LDAP-20（6 处文案包数错）/ G-LDAP-21（`ldap_attributes_custom` notes 措辞不准）。自审 3 轮，末轮干净（§10.1）。
- **自审轮次结论**：**自审 4 轮，末轮干净**。逐轮（每轮的机读脚本与结论）：
  - **轮 1**：机读复核 22 例 ID 集合/顺序/`packet_count`/`expect` 键集合/`fields`+`frames` 计数/链形/顶层键 —— **全对**。
  - **轮 2**：复算 BER 长度表逐条对 JSON frames hex（`30 84 00 00 00 10`/`01 58`/`00 05`/`60 84 … 07`）—— **全对**；包数公式 16/16 —— **全对**；文案数字扫描 —— **首扫只发现 4 处**（正则 `(\d+)\s*包`）。
  - **轮 3**：对账表逐表重数 —— **发现两处计数错并修正**：① 设计 §10.2 矩阵原写"覆 22 + A′ 8 + 不适用 3"，逐格清点实为 **覆 19 + A′ 9 + 不适用 5**（原值 T2 列多算 1、T3 列少算 1、不适用少算 2）；② 设计 §10.3 变体原写"覆 34 + 立项 13"，逐行清点实为 **覆 36 + 立项 11**（3 个"覆 + 补面"复合行的主分类口径不明导致）。修正后总账 = 覆 72 + 立项 23 + 不适用 12 = 107 ✓
  - **轮 4**：① **发现 §10.3 行 4 `rounds` 上界算错**：原写 `rounds ≤ 10921`，按 `1+3(rounds-1)+2 ≤ 32767` 解出 **10922**（10922 → maxID 32766 ✓；10923 → 32769 ✗），已改 3 处；② **发现 G-LDAP-20 漏 1 处文案**：扩扫（除 `N 包` 外加入 `(挥手|done|unbind)\s*=\s*(\d+)`）后命中 **6 处**而非 5 处——漏的是 `ldap_message_id_increment` notes 的 `挥手=17`（正确 18）；**该漏检本身即"正则只认 `N 包` 扫不全"的实例**，已写入 G-LDAP-20 的口径注。**末轮（第 4 轮修正后复跑全部机读检查）无新发现**。

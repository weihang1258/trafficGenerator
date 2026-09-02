# GBT（GetBlockTemplate，BIP 22/23 区块模板 RPC）测试用例契约

> 版本：v2.0.0（测试用例）
> 日期：2026-09-02
> 配套设计：`docs/protocol-designs/77-gbt-design.md`（v2.0.0）
> 机器契约：`trafficgen/test/protocol_pcap/cases/gbt.json`（proto key：`gbt`；本版不写文件，当前 JSON 仅含注册前置占位）
> 状态：按《协议设计文档与用例文档需求文档 v1.3》重写级修复轮产物：20 → **81 例（53 正 + 28 负）**，待复验关闭。

## 1. 测试原则和未注册边界

用例从设计 §2–§8 逐项派生，按 v1.3 行为面全枚举扩量，共 **81 个唯一语义 ID：53 个正例 + 28 个负例**（对应审查枚举 114 行为面点）。派生规则：设计 §3.1 每个交互行、§3.2 每个方法/参数形态、§3.3 每个模板键约束、§3.4 每条公式、§5 每条会话/终止口径、§7 每行错误处理在本文有对应断言；**一个用例只验证一个协议行为**（v1.3 §7 原子原则）。

**TSHARK 实测基线（本机 3.6.14，2026-09-01，构造 pcap 实证 /tmp/gbt_v13/{probe,probe2}.pcap，非臆造）**：
1. 本机**无 gbt 专用 dissector**；断言不依赖 gbt.* 字段。
2. **8332 与 18332 端口 HTTP POST 均无需 decode-as 即自动解出**（TCP 路径启发式识别；probe frame 9 实测 18332 同载荷 http+json 全解）；**无 DecodeAs 依赖**。
3. 可用断言字段：`http.request.method`/`http.response.code`（200/401/500 三态实测）/`http.content_type`/`http.content_length`（精确值）/`http.authorization`（`Basic dXNlcjpwYXNz` 精确断言可行）/`http.file_data`；**`Content-Type: application/json` 触发 JSON 子解析**——`json.key`（逗号拼接键序）/`json.value.string`/`json.value.number`（逗号拼接值）。实测命中：请求侧键序 `jsonrpc,id,method,rules,capabilities,params` 值串 `1.0,rpc-1,getblocktemplate,segwit,longpoll`；200 模板侧全部键展开（previousblockhash 64-hex/target 64-hex/bits 8-hex/noncerange 16-hex/coinbasevalue=5000000000 大整数精确断言可行）；401/500 侧 error 的 code/message 逐值解出。
4. **断言纪律**：json.* 为全文拼接单串、harness 无包含谓词——整串精确断言仅 fixture 钉死全部键序/值时可用（本版 fixture 全量钉死，§3）；动态值（跨事务 curtime/longpollid 变体）用 json.key 整串形态 + frames hex 兜底 + nonzero；键存在性 = 整串匹配。
5. 偏移：无 VLAN/options 时 HTTP 起行 IPv4 offset 54 / IPv6 74；JSON body 起点 = 54/74 + 固定头集合字节长。

**pcap/NIC 双输出契约（G-8）**：pcap 与 `port_group`/NIC 两种输出路径使用同一份用例契约——同一组语义 ID、同一包数约定、同一断言集，不含输出路径专有断言（与 64-cwmp/66-doh/76-getwork 同形）。v1.0.0 的独立 pcap_nic 一致性用例删除（测试方法非协议语义，hl7 判例）。

当前 JSON 只保留 `gbt_neg_unregistered` 注册前置占位：`proto=gbt`、`expect_error=true`、`error_contains` 精确为 `unknown layer`；不计入 81 个语义 ID。注册后移除占位，按本文 §2（53 正例）+ §5（28 负例）顺序补入。

## 2. 原子用例索引

| # | ID | 类型 | 覆盖（设计 §） | 约定 packet_count |
|---:|---|---|---|---:|
| 1 | `gbt_template_ipv4_8332` | 正 | §1/§2：IPv4/TCP/HTTP 8332 基线（取模板、id 配对）；BIP 22 | 9 |
| 2 | `gbt_template_ipv6_8332` | 正 | §2：IPv6 fixture（ipv6.nxt=6、offset 74） | 9 |
| 3 | `gbt_port_nondefault_18332` | 正 | §2：非默认端口 18332 显式声明（免 DecodeAs 实测） | 9 |
| 4 | `gbt_auth_basic_header` | 正 | §1/§3.1：Authorization: Basic dXNlcjpwYXNz 在场 | 9 |
| 5 | `gbt_http401_noauth` | 正 | §3.1：无凭证 → 401 + WWW-Authenticate、空 body | 9 |
| 6 | `gbt_http500_rpc_error` | 正 | §3.1：HTTP 500 + error 对象（code/message、id 保留） | 9 |
| 7 | `gbt_jsonrpc10_default` | 正 | §3.2：bitcoin-cli 形态（请求 jsonrpc:"1.0"、响应无该成员） | 9 |
| 8 | `gbt_jsonrpc20_form` | 正 | §3.2：2.0 观测形态（请求/响应均前置 jsonrpc:"2.0"） | 9 |
| 9 | `gbt_id_numeric_sequence` | 正 | §3.2/§5：keep-alive 三事务 id 1/2/3 递增配对 | 13 |
| 10 | `gbt_id_string_form` | 正 | §3.2：字符串 id "rpc-001" | 9 |
| 11 | `gbt_host_header_value` | 正 | §3.1：Host 头精确值 | 9 |
| 12 | `gbt_http10_close` | 正 | §3.1：HTTP/1.0 + close + 单事务后 FIN | 9 |
| 13 | `gbt_empty_params_form` | 正 | §3.2：基线 params 恰 [] | 9 |
| 14 | `gbt_rules_request` | 正 | §3.2：params[0].rules=["segwit"] 请求形态 | 9 |
| 15 | `gbt_capabilities_response` | 正 | §3.3：模板 capabilities=["proposal"]（服务器能力） | 9 |
| 16 | `gbt_id_large_value` | 正 | §3.2：边界大数值 id 2147483647 | 9 |
| 17 | `gbt_template_keyset` | 正 | §3.3：模板 18 顶层键序整串断言 | 9 |
| 18 | `gbt_prevhash_64hex` | 正 | §3.3：previousblockhash 恰 64 hex | 9 |
| 19 | `gbt_target_64hex` | 正 | §3.3：target 恰 64 hex | 9 |
| 20 | `gbt_bits_8hex` | 正 | §3.3：bits 恰 8 hex | 9 |
| 21 | `gbt_noncerange_16hex` | 正 | §3.3：noncerange 恰 16 hex | 9 |
| 22 | `gbt_height_value` | 正 | §3.3：height 正整数 1000 精确断言 | 9 |
| 23 | `gbt_coinbasevalue_bigint` | 正 | §3.3：coinbasevalue=5000000000 大整数精确 | 9 |
| 24 | `gbt_mintime_curtime` | 正 | §3.3：mintime=1756684800 / curtime=1756685100 | 9 |
| 25 | `gbt_mutable_values` | 正 | §3.3：mutable 定义值 ["time","transactions","prevblock"] | 9 |
| 26 | `gbt_coinbaseaux_flags` | 正 | §3.3：coinbaseaux.flags=706f6f6c31（矿池标签 hex） | 9 |
| 27 | `gbt_transactions_empty` | 正 | §3.3：transactions 恰空数组形态 | 9 |
| 28 | `gbt_transactions_elements` | 正 | §3.3：1 tx 元素 6 键（data/txid/hash/depends/fee/sigops，响应 body 884B） | 9 |
| 29 | `gbt_limits_values` | 正 | §3.3：sigoplimit=80000 / sizelimit=4000000 标量 | 9 |
| 30 | `gbt_longpoll_uri_field` | 正 | §3.3：模板 longpolluri 字段在场（BIP 22，G-11） | 9 |
| 31 | `gbt_longpoll_request` | 正 | §3.1/§5：longpolluri 独立请求 + 挂起返回新模板 | 11 |
| 32 | `gbt_longpollid_parameter` | 正 | §3.2：params[0].longpollid 参数形态 | 9 |
| 33 | `gbt_workid_template` | 正 | §3.3：模板 workid="w-1" 在场 | 9 |
| 34 | `gbt_submitblock_with_workid` | 正 | §3.2/§3.5：submitblock [hexdata, workid] 双参回传 | 11 |
| 35 | `gbt_template_refresh` | 正 | §5：再取模板 height+1/curtime+600（distinct） | 11 |
| 36 | `gbt_submitblock_accepted` | 正 | §3.5：result:null 接受（null 非错误） | 11 |
| 37 | `gbt_submitblock_rejected_reason` | 正 | §3.5：result:"prev-blk-not-found" 拒绝（正例形态） | 11 |
| 38 | `gbt_submitblock_error_500` | 正 | §3.1：提交后 500 + error 对象 | 9 |
| 39 | `gbt_proposal_mode` | 正 | §3.2：mode=proposal+data → result:true（BIP 23） | 11 |
| 40 | `gbt_proposal_reject` | 正 | §3.5：proposal 拒绝 reason 观测（正例形态） | 11 |
| 41 | `gbt_keepalive_multi_transaction` | 正 | §5：keep-alive 三事务、按 CL 分界 | 13 |
| 42 | `gbt_keepalive_then_close` | 正 | §3.1/§5：复用两事务后末响应 close + FIN | 11 |
| 43 | `gbt_body_mss_spanning` | 正 | §5：三响应打包 1752B（3×584B）跨两段、按 `tcp.stream` 重组 | 10 |
| 44 | `gbt_multi_body_single_segment` | 正 | §5：两事务请求/响应各粘单段 | 9 |
| 45 | `gbt_multi_session` | 正 | §5：双会话按序展开（第二会话包号 = 前会话+1） | 18 |
| 46 | `gbt_concurrent_sessions` | 正 | §5：concurrent:true 双会话交织（tcp.stream distinct） | 18 |
| 47 | `gbt_session_state_isolation` | 正 | §5：双会话各两事务、最近模板/id 互不串用 | 22 |
| 48 | `gbt_retry_after_500` | 正 | §5：同连接 500 后重试（新 id） | 11 |
| 49 | `gbt_reconnect_new_stream` | 正 | §5：干净关闭后新四元组新连接（tcp.stream distinct） | 18 |
| 50 | `gbt_rst_interrupt` | 正 | §5：RST 中断（tcp.flags.reset=1、无 FIN） | 5 |
| 51 | `gbt_no_frames_after_fin` | 正 | §5：FIN×2 后无新业务帧、全流无 RST | 9 |
| 52 | `gbt_dual_family` | 正 | §4：v4+v6 双会话并行 | 18 |
| 53 | `gbt_template_large_mss` | 正 | §5：大模板 5512B 响应跨 4 段重组 | 12 |
| 54 | `gbt_neg_bad_json` | 负 | §7：body 非合法 JSON | — |
| 55 | `gbt_neg_body_truncated` | 负 | §7：body 截断 | — |
| 56 | `gbt_neg_content_length_mismatch` | 负 | §7：Content-Length 不符 | — |
| 57 | `gbt_neg_unknown_method` | 负 | §7：未知 method（getwork 归口） | — |
| 58 | `gbt_neg_template_params_nonobject` | 负 | §7：params[0] 非对象 | — |
| 59 | `gbt_neg_submitblock_no_hexdata` | 负 | §7：submitblock 缺 hexdata | — |
| 60 | `gbt_neg_submitblock_third_param` | 负 | §7：submitblock 三参数 | — |
| 61 | `gbt_neg_prevhash_length` | 负 | §7：prevhash 长度错 | — |
| 62 | `gbt_neg_bits_length` | 负 | §7：bits 长度错 | — |
| 63 | `gbt_neg_noncerange_length` | 负 | §7：noncerange 长度错 | — |
| 64 | `gbt_neg_target_length` | 负 | §7：target 长度错 | — |
| 65 | `gbt_neg_field_missing` | 负 | §7：模板缺 height | — |
| 66 | `gbt_neg_workid_mismatch` | 负 | §7：workid 错配 | — |
| 67 | `gbt_neg_id_mismatch` | 负 | §7：响应 id 错配 | — |
| 68 | `gbt_neg_longpollid_missing` | 负 | §7：longpoll 缺 longpollid | — |
| 69 | `gbt_neg_longpollid_stale` | 负 | §7：longpollid 陈旧 | — |
| 70 | `gbt_neg_height_nonincrement` | 负 | §7：刷新模板 height 未 +1 | — |
| 71 | `gbt_neg_mode_invalid` | 负 | §7：mode 值域外 | — |
| 72 | `gbt_neg_unknown_rule` | 负 | §7：未知 rule | — |
| 73 | `gbt_neg_bip9_field` | 负 | §7：vbavailable/vbrequired 归口 | — |
| 74 | `gbt_neg_witness_commitment` | 负 | §7：default_witness_commitment 归口 | — |
| 75 | `gbt_neg_coinbasetxn_form` | 负 | §7：coinbasetxn 形态归口 | — |
| 76 | `gbt_neg_line_profile` | 负 | §7：jsonrpc-line 臆造形态归口 | — |
| 77 | `gbt_neg_udp_carrier` | 负 | §7：UDP 载体 | — |
| 78 | `gbt_neg_port_undeclared` | 负 | §7：端口未声明 | — |
| 79 | `gbt_neg_address_family` | 负 | §7：地址族冲突 | — |
| 80 | `gbt_neg_http_method_get` | 负 | §7：GET 方法承载 | — |
| 81 | `gbt_neg_error_propagation` | 负 | §7：错误被吞假成功 | — |

**包数约定**（设计 §5）：单事务 = 3+2+4 = 9；keep-alive N 事务 = 7+2N；大模板/跨段按实际段数（ceil(响应字节/1460)）；RST = 5；重连/多会话 = Σ连接。

## 3. 线上编码和偏移断言

**fixture 常量**（设计 §3.4 同源，全部程序复算钉死）：IPv4 `192.0.2.77:4077 → 198.51.100.77:8332`；IPv6 `2001:db8::77 → 2001:db8:100:77`；非默认 18332；auth `dXNlcjpwYXNz`；id 1/2/3/4/5、`"rpc-001"`、`2147483647`；模板 18 键 = 设计 §3.3 fixture 列（prevhash=`11`×32、target=`00000000ffff`+`00`×26、bits=`1d00ffff`、noncerange=`00000000ffffffff`、height=1000、coinbasevalue=5000000000、mintime=1756684800、curtime=1756685100、mutable 三值、flags=`706f6f6c31`、sigoplimit=80000、sizelimit=4000000、longpollid=`lp-1000-1`、longpolluri=`http://198.51.100.77:8332/longpoll`、capabilities=`["proposal"]`、workid=`w-1`）；刷新模板 height=1001/curtime=1756685700/longpollid=`lp-1001-1`；tx 元素 data=`02`+`ab`×99+`aa`（202 hex）/txid=`22`×32/hash=`33`×32/depends=[]/fee=1000/sigops=1；submitblock hexdata=`aa`×80；大模板 = 3 tx 元素 data=`ff`×740；500 错误 code=-1/message=`getblocktemplate: unsupported rule`；proposal 拒绝 reason=`prev-blk-not-found`。

**核心行字节基线**（hex 大写；CRLF=`0D0A`）：

| 消息 | 全长 | hex |
|---|---:|---|
| 基线请求（头+body，含 Authorization，全长 220B） | 220 | `504F5354202F20485454502F312E310D0A486F73743A203139382E35312E3130302E37373A383333320D0A417574686F72697A6174696F6E3A2042617369632064584E6C636A707759584E7A0D0A436F6E74656E742D547970653A206170706C69636174696F6E2F6A736F6E0D0A436F6E74656E742D4C656E6774683A2036340D0A436F6E6E656374696F6E3A206B6565702D616C6976650D0A0D0A7B226A736F6E727063223A22312E30222C226964223A312C226D6574686F64223A22676574626C6F636B74656D706C617465222C22706172616D73223A5B5D7D` |
| 基线请求 body（id=1，全长 64B） | 64 | `7B226A736F6E727063223A22312E30222C226964223A312C226D6574686F64223A22676574626C6F636B74656D706C617465222C22706172616D73223A5B5D7D` |
| 模板响应（头 96B + body 607B，全长 703B） | 703 | 头 96B `485454502F312E3120323030204F4B0D0A436F6E74656E742D547970653A206170706C69636174696F6E2F6A736F6E0D0A436F6E74656E742D4C656E6774683A203630370D0A436F6E6E656374696F6E3A206B6565702D616C6976650D0A0D0A` + body 607B = 下两行前缀 96B + 中段 447B（fixture 生成）+ 后缀 64B |
| 模板响应 body 前缀（96B） | — | `7B22726573756C74223A7B2276657273696F6E223A3533363837303931322C2270726576696F7573626C6F636B68617368223A223131313131313131313131313131313131313131313131313131313131313131313131313131313131313131` |
| 模板响应 body 后缀（64B） | — | `226361706162696C6974696573223A5B2270726F706F73616C225D2C22776F726B6964223A22772D31227D2C226572726F72223A6E756C6C2C226964223A317D` |
| 接受响应 body（result:null，id=4） | 35 | `7B22726573756C74223A6E756C6C2C226572726F72223A6E756C6C2C226964223A347D` |
| 拒绝理由响应 body（id=4） | 51 | `7B22726573756C74223A22707265762D626C6B2D6E6F742D666F756E64222C226572726F72223A6E756C6C2C226964223A347D` |
| 500 错误响应 body（id=5） | 89 | `7B22726573756C74223A6E756C6C2C226572726F72223A7B22636F6465223A2D312C226D657373616765223A22676574626C6F636B74656D706C6174653A20756E737570706F727465642072756C65227D2C226964223A357D` |

断言分层：①载体——设备帧 `tcp.srcport=4077`、`tcp.dstport=8332`（变体 18332）、`ip.version=4`/`ipv6.nxt=6`；②HTTP——`http.request.method=POST`、`http.response.code∈{200,401,500}`、`http.content_length` 精确值（64/607/35/51/89）、`http.authorization="Basic dXNlcjpwYXNz"`；③JSON——`json.key` 整串（请求 `jsonrpc,id,method,params`；模板 18 键序 `version,previousblockhash,transactions,coinbaseaux,coinbasevalue,target,mintime,mutable,noncerange,sigoplimit,sizelimit,curtime,bits,height,longpollid,longpolluri,capabilities,workid`）、`json.value.number` 数值串（含 5000000000）、`json.value.string` 值串；普通模板 body 488B（含 14 必选键）/ 1-tx 模板 body 884B / 大模板 body 5512B；④frames hex——短消息全 hex、长消息前缀+后缀（§3 表）；⑤重组——跨段/粘连按 `tcp.stream` 重组后断整消息。

## 4. 正例逐项断言契约

1. **`gbt_template_ipv4_8332`**（9 = 3+2+4）：帧 4 请求（offset 54）——`http.request.method=POST`、`http.content_length=64`、body 全 hex（§3 表）；帧 5 响应 `http.response.code=200`、CL=607、json.path=/id 与请求同值。
2. **`gbt_template_ipv6_8332`**（9）：同 1 + `ipv6.nxt=6`、offset 74、fixture 地址、不出现 v4 地址。
3. **`gbt_port_nondefault_18332`**（9）：`tcp.dstport=18332`（配置显式声明）、断言集与 1 全同（§1 基线②——免 DecodeAs）。
4. **`gbt_auth_basic_header`**（9）：`http.authorization="Basic dXNlcjpwYXNz"`、frames hex 头区含 `417574686F72697A6174696F6E3A2042617369632064584E6C636A707759584E7A`。
5. **`gbt_http401_noauth`**（9）：请求无 Authorization 头；响应 `http.response.code=401`、`WWW-Authenticate: Basic realm="jsonrpc"`、`http.content_length=0`、无 JSON body。
6. **`gbt_http500_rpc_error`**（9）：响应 `http.response.code=500`、body 89B 全 hex、`json.value.number` 含 −1、`json.value.string` 含 unsupported rule、`json.path=/id` 保留 id=5、`json.path=/result` 值 null。
7. **`gbt_jsonrpc10_default`**（9）：请求 body 64B 全 hex（含 `"jsonrpc":"1.0"` 前置成员——frames hex 头区 `7B226A736F6E727063223A22312E3022`）；**响应 json.key 不含 jsonrpc**（bitcoin-cli 形态）。
8. **`gbt_jsonrpc20_form`**（9）：请求 body 前置 `{"jsonrpc":"2.0"`、响应同形（json.key 首位 jsonrpc）。
9. **`gbt_id_numeric_sequence`**（13 = 7+2×3）：三事务 `json.path=/id` 递增 1/2/3、响应与请求同值配对。
10. **`gbt_id_string_form`**（9）：id=`"rpc-001"` 字符串类型（json.value.string 在场）。
11. **`gbt_host_header_value`**（9）：frames hex 头区 `486F73743A203139382E35312E3130302E37373A38333332` 精确在场。
12. **`gbt_http10_close`**（9）：请求行 HTTP/1.0、无 Host；响应 close；单事务后 FIN×2。
13. **`gbt_empty_params_form`**（9）：`json.path=/params` 恰空数组（body 尾区 `22706172616D73223A5B5D7D`）。
14. **`gbt_rules_request`**（9）：请求 body 84B——params[0] = `{"rules":["segwit"]}`（json.key 含 rules、json.value.string 含 segwit）。
15. **`gbt_capabilities_response`**（9）：模板 `json.path=/result/capabilities` = `["proposal"]`（json.value.string 含 proposal）。
16. **`gbt_id_large_value`**（9）：id=2147483647、body 长度 45+10+16+2=73B（§3.4 公式复核）。
17. **`gbt_template_keyset`**（9）：模板响应 json.key 整串 = §3 键序（18 顶层键 + result/error/id 外层）——键序整串匹配。
18. **`gbt_prevhash_64hex`**（9）：`json.path=/result/previousblockhash` 值恰 64 hex 且 = `11`×32（frames hex 头区可对 `3131…` 段）。
19. **`gbt_target_64hex`**（9）：`json.path=/result/target` 值恰 64 hex（前 12 hex=`00000000ffff`、后 52 全 `00`）。
20. **`gbt_bits_8hex`**（9）：`json.path=/result/bits` 值恰 8 hex = `1d00ffff`。
21. **`gbt_noncerange_16hex`**（9）：`json.path=/result/noncerange` 值恰 16 hex = `00000000ffffffff`。
22. **`gbt_height_value`**（9）：`json.path=/result/height` 值 1000 精确（json.value.number）。
23. **`gbt_coinbasevalue_bigint`**（9）：`json.path=/result/coinbasevalue` 值 5000000000 精确（大整数逐位——probe 实测可行）。
24. **`gbt_mintime_curtime`**（9）：mintime=1756684800、curtime=1756685100 双值精确（curtime ≥ mintime）。
25. **`gbt_mutable_values`**（9）：`json.path=/result/mutable` = `["time","transactions","prevblock"]` 三定义值（json.value.string 含 time,transactions,prevblock）。
26. **`gbt_coinbaseaux_flags`**（9）：`json.path=/result/coinbaseaux.flags` 值 `706f6f6c31`（hex 矿池标签）。
27. **`gbt_transactions_empty`**（9）：`json.path=/result/transactions` 恰空数组（body 含 `227472616E73616374696F6E73223A5B5D`）。
28. **`gbt_transactions_elements`**（9）：带 1 交易模板（响应 body 884B）——json.key 含 tx 元素 6 键 `data,txid,hash,depends,fee,sigops`、fee=1000/sigops=1 精确、txid=`22`×32。
29. **`gbt_limits_values`**（9）：sigoplimit=80000、sizelimit=4000000 标量精确（BIP 145 对象形态不产生——断言即标量）。
30. **`gbt_longpoll_uri_field`**（9）：`json.path=/result/longpolluri` 值 `http://198.51.100.77:8332/longpoll` 精确（BIP 22，G-11）。
31. **`gbt_longpoll_request`**（11 = 3+4+4）：事务 1 取模板（含 longpolluri/longpollid）；事务 2 **POST 该 URI**（请求行 `POST /longpoll HTTP/1.1`——非 `/`）、params 携 longpollid、响应 = 刷新模板（height=1001）。
32. **`gbt_longpollid_parameter`**（9）：请求 body 90B——params[0] = `{"longpollid":"lp-1000-1"}`（json.key 含 longpollid、值精确）。
33. **`gbt_workid_template`**（9）：`json.path=/result/workid` 值 `w-1` 精确。
34. **`gbt_submitblock_with_workid`**（11）：事务 2 提交 body 227B——params 双元素（hexdata + `w-1`）、`json.path=/params` 数组长度恰 2；响应 35B。
35. **`gbt_template_refresh`**（11）：两取模板事务——第二模板 height=1001/curtime=1756685700/longpollid=`lp-1001-1` 与首模板 distinct（json.value 三值对比）。
36. **`gbt_submitblock_accepted`**（11）：事务 2 提交（单参 221B）→ 响应 body 35B 全 hex、`json.path=/result` 值 **null**（BIP 22 接受语义）且 `/error` 值 null。
37. **`gbt_submitblock_rejected_reason`**（11）：响应 body 51B 全 hex、`json.path=/result` 值字符串 `prev-blk-not-found`（拒绝是正例形态）。
38. **`gbt_submitblock_error_500`**（9）：单事务——提交请求 → 500 + error 对象（89B 形态同 §3 表）、id 保留。
39. **`gbt_proposal_mode`**（11）：事务 2 请求 body 295B——params[0] = `{"mode":"proposal","data":"<202 hex>"}`；响应 `json.path=/result` 值 **true**（BIP 23 通过）。
40. **`gbt_proposal_reject`**（11）：同 39 形态但响应 result=`"reason"` 字符串（观测正例）。
41. **`gbt_keepalive_multi_transaction`**（13 = 7+2×3）：三事务 `http.connection=keep-alive` 恒定、无中间 FIN、按 CL 拆三对、id 各配对。
42. **`gbt_keepalive_then_close`**（11）：前两事务 keep-alive、末响应 close、随后 FIN×2。
43. **`gbt_body_mss_spanning`**（10 = 3+1+2+4）：三普通模板（14 必选键，单响应全长 584B=96 头+488 body，×3=1752B）打包跨两段——按 `tcp.stream` 重组后逐响应断 CL=488 与 json.path=/id 递增；单段不得断整消息。
44. **`gbt_multi_body_single_segment`**（9 = 3+1+1+4）：两事务请求粘一段（2×64=128B）、响应粘一段（全长 703+131=834B）——按 CL 边界拆分；段边界 ≠ 消息边界双向断言。
45. **`gbt_multi_session`**（18 = 9+9）：会话 2（src_port 4078）握手包号 = 10、`tcp.stream` 两值 distinct、id 序列独立。
46. **`gbt_concurrent_sessions`**（18 = 9+9）：`concurrent: true` 双会话交织——两 `tcp.stream` distinct、帧序交织（会话 2 首帧先于会话 1 FIN）、各会话事务配对完整不放宽、模板/id 跨流不串。
47. **`gbt_session_state_isolation`**（22 = 11+11）：两会话各两事务；会话 2 提交 workid 引用本流模板、两流 id 序列同值 1/2 但不跨流配对。
48. **`gbt_retry_after_500`**（11 = 3+2+2+4）：请求 id=5 → 500（89B）→ 重试 id=6 → 200 模板——重试新 id 新 body、500 后无 FIN。
49. **`gbt_reconnect_new_stream`**（18 = 9+9）：连接 1 干净 FIN；连接 2 新四元组（src_port 4079）新模板上下文（height 变体）——`tcp.stream` distinct。
50. **`gbt_rst_interrupt`**（5 = 3+1+1）：握手 3 + 请求 1 + RST 1（`tcp.flags.reset=1`）——无响应 body、无 FIN。
51. **`gbt_no_frames_after_fin`**（9）：单事务 + FIN×2——包数恰 9、末帧后无 `tcp.len>0` 帧、全流无 RST。
52. **`gbt_dual_family`**（18 = 9+9）：v4 + v6 会话各单事务——`ip.version` 各 4/6、两流状态独立。
53. **`gbt_template_large_mss`**（12 = 3+1+4+4）：大模板（3×740 hex data，响应 body 5512B）单响应跨 4 段——按 `tcp.stream` 重组后断 CL=5512、json.key 含三 tx 元素 data 键、各段 `tcp.len` 之和 = 5512+96=5609（头）。

## 5. 负例契约

每个负例必须在 planner/validator 阶段失败并传播为 task error，不得产生成功 PCAP、`completed/0 packet` 或只剩 TCP/HTTP 外壳的假成功。执行期 `expect` 键集合严格为 `{"expect_error", "error_contains"}`。**逐故障原子拆分：一行一例、主锚词钉死（备选括注）**，与设计 §7 表逐行同序（28 行）：

| # | ID | `wire_fault` | 故障输入（单一注入） | 主锚词（备选） |
|---:|---|---|---|---|
| 54 | `gbt_neg_bad_json` | `bad_json` | 声明的 body 序列化后非合法 JSON | `json` |
| 55 | `gbt_neg_body_truncated` | `body_truncated` | body 截断（Content-Length 大于实际） | `truncat`（body） |
| 56 | `gbt_neg_content_length_mismatch` | `content_length_mismatch` | Content-Length ≠ 实际 body 字节数 | `content-length` |
| 57 | `gbt_neg_unknown_method` | `unknown_method` | method 取支持集外值（如 `getwork`——族分立） | `method`（unknown） |
| 58 | `gbt_neg_template_params_nonobject` | `template_params_nonobject` | getblocktemplate params[0] 非对象（如字符串） | `params`（template） |
| 59 | `gbt_neg_submitblock_no_hexdata` | `submitblock_no_hexdata` | submitblock params 缺 hexdata（空数组） | `params`（submitblock） |
| 60 | `gbt_neg_submitblock_third_param` | `submitblock_third_param` | submitblock 三参数（BIP 22 至多双参） | `params`（submitblock） |
| 61 | `gbt_neg_prevhash_length` | `prevhash_length` | previousblockhash ≠ 64 hex | `length`（prevhash） |
| 62 | `gbt_neg_bits_length` | `bits_length` | bits ≠ 8 hex | `length`（bits） |
| 63 | `gbt_neg_noncerange_length` | `noncerange_length` | noncerange ≠ 16 hex | `length`（noncerange） |
| 64 | `gbt_neg_target_length` | `target_length` | target ≠ 64 hex | `length`（target） |
| 65 | `gbt_neg_field_missing` | `field_missing` | 模板缺任一必选键（注入 height 缺失） | `height`（missing） |
| 66 | `gbt_neg_workid_mismatch` | `workid_mismatch` | submitblock workid 与本会话最近模板不符 | `workid`（mismatch） |
| 67 | `gbt_neg_id_mismatch` | `id_mismatch` | 响应 id 与请求 id 不一致 | `id`（mismatch） |
| 68 | `gbt_neg_longpollid_missing` | `longpollid_missing` | longpoll 请求 params 缺 longpollid（BIP 22） | `longpollid`（missing） |
| 69 | `gbt_neg_longpollid_stale` | `longpollid_stale` | longpollid 非本会话最近模板的 ID（陈旧） | `longpollid`（stale） |
| 70 | `gbt_neg_height_nonincrement` | `height_nonincrement` | 刷新模板 height 未 +1（同值或回退） | `height`（increment） |
| 71 | `gbt_neg_mode_invalid` | `mode_invalid` | options.mode 取值域外（如 `"template-x"`） | `mode` |
| 72 | `gbt_neg_unknown_rule` | `unknown_rule` | rules 含支持集 {segwit} 外值（如 `"taproot"`） | `rule`（unknown） |
| 73 | `gbt_neg_bip9_field` | `bip9_field` | 模板注入 vbavailable/vbrequired（BIP 9 边界归口） | `unsupported`（bip9） |
| 74 | `gbt_neg_witness_commitment` | `witness_commitment` | 模板注入 default_witness_commitment（BIP 145 归口） | `unsupported`（witness） |
| 75 | `gbt_neg_coinbasetxn_form` | `coinbasetxn_form` | 模板注入 coinbasetxn 完整形态 | `unsupported`（coinbasetxn） |
| 76 | `gbt_neg_line_profile` | `line_profile` | profile 取 jsonrpc-line（臆造形态归口） | `carrier`（profile） |
| 77 | `gbt_neg_udp_carrier` | `udp_carrier` | UDP 载体（仅 TCP 上的 HTTP 合法） | `carrier`（udp） |
| 78 | `gbt_neg_port_undeclared` | `port_undeclared` | 非 8332/18332 端口未显式声明 | `port`（undeclared） |
| 79 | `gbt_neg_address_family` | `address_family` | IPv6 地址配 IPv4 层链（或反向） | `family`（address） |
| 80 | `gbt_neg_http_method_get` | `http_method_get` | GET 方法承载（必须 POST） | `post`（method） |
| 81 | `gbt_neg_error_propagation` | `error_propagation` | 注入 wire_fault=bad_json 已知非法配置，断言任务以 task error 终止（含底层锚词）而非 completed/0 packet 假成功 | `propagat`（error） |

**不得误报**（设计 §7 同款）：result:null（36）、result:"reason"（37/40）、proposal true（39）、500（6/38）、401（5）、HTTP/1.0（12）、2.0 形态（8）、空 transactions（27）、字符串 id（10）。

## 6. 五层覆盖映射

| 层 | 用例 |
|---|---|
| 功能层 | 1-16（载体/形态/id/rules）、36-40（提交三态）、54-81（负例逐故障） |
| 性能层 | 43（打包跨段）、44（粘连）、53（大模板跨 MSS） |
| 数据场景层 | 17-29（模板 18 键逐键）、30/33（longpolluri/workid） |
| 地址与流层 | 2/52（IPv6/双栈）、3（18332）、45-47（多会话/并发/隔离）、48-51（重试/重连/RST/FIN） |
| 业务层 | 31（longpoll 挂起）、35（模板刷新）、34（workid 关联） |

## 7. 机器契约与静态检查

1. `python3 -m json.tool trafficgen/test/protocol_pcap/cases/gbt.json` 通过；当前数组恰含 1 条 `gbt_neg_unregistered`：`proto=gbt`、`expect_error=true`、`error_contains` 精确为 `unknown layer`。
2. **注册同步项（G-20）**：注册替换占位时同步修正 JSON 占位期陈旧 notes（"14 positive and 6 negative"旧稿统计）为本文 §2 各行覆盖描述——占位期不改 JSON，登记为注册时必做项。
3. 正例断言键集：`fields`（http.*/json.*）+ `frames`（hex 前/后缀或全量）+ `min_packets`；负例键集恰 `{expect_error, error_contains}`。
4. 三方一致性：设计 §6 wire_fault 枚举 28 值 = 设计 §7 表 28 行 = 本文 §5 表 28 行，同序同词；ID 权威 = 本文 §2（设计 §9 簇级图景）。
5. **协议事实哨兵（G-4/G-6/G-11 回归防护）**：任何文档/断言出现层链 `[ip,tcp,gbt]`（无 http）、`jsonrpc-line` profile、longpoll"下一次 params 提交 ID"旧描述，即为回归错误。

## 8. 三方一致性表

设计 §9（ID 权威声明）、本文 §2（#1–#53 正例）+ §5（#54–#81 负例）、实现后 `gbt.json` 保持同一 81 个语义 ID、同一顺序（当前 JSON 另有占位，不计入）：

```text
gbt_template_ipv4_8332
gbt_template_ipv6_8332
gbt_port_nondefault_18332
gbt_auth_basic_header
gbt_http401_noauth
gbt_http500_rpc_error
gbt_jsonrpc10_default
gbt_jsonrpc20_form
gbt_id_numeric_sequence
gbt_id_string_form
gbt_host_header_value
gbt_http10_close
gbt_empty_params_form
gbt_rules_request
gbt_capabilities_response
gbt_id_large_value
gbt_template_keyset
gbt_prevhash_64hex
gbt_target_64hex
gbt_bits_8hex
gbt_noncerange_16hex
gbt_height_value
gbt_coinbasevalue_bigint
gbt_mintime_curtime
gbt_mutable_values
gbt_coinbaseaux_flags
gbt_transactions_empty
gbt_transactions_elements
gbt_limits_values
gbt_longpoll_uri_field
gbt_longpoll_request
gbt_longpollid_parameter
gbt_workid_template
gbt_submitblock_with_workid
gbt_template_refresh
gbt_submitblock_accepted
gbt_submitblock_rejected_reason
gbt_submitblock_error_500
gbt_proposal_mode
gbt_proposal_reject
gbt_keepalive_multi_transaction
gbt_keepalive_then_close
gbt_body_mss_spanning
gbt_multi_body_single_segment
gbt_multi_session
gbt_concurrent_sessions
gbt_session_state_isolation
gbt_retry_after_500
gbt_reconnect_new_stream
gbt_rst_interrupt
gbt_no_frames_after_fin
gbt_dual_family
gbt_template_large_mss
gbt_neg_bad_json
gbt_neg_body_truncated
gbt_neg_content_length_mismatch
gbt_neg_unknown_method
gbt_neg_template_params_nonobject
gbt_neg_submitblock_no_hexdata
gbt_neg_submitblock_third_param
gbt_neg_prevhash_length
gbt_neg_bits_length
gbt_neg_noncerange_length
gbt_neg_target_length
gbt_neg_field_missing
gbt_neg_workid_mismatch
gbt_neg_id_mismatch
gbt_neg_longpollid_missing
gbt_neg_longpollid_stale
gbt_neg_height_nonincrement
gbt_neg_mode_invalid
gbt_neg_unknown_rule
gbt_neg_bip9_field
gbt_neg_witness_commitment
gbt_neg_coinbasetxn_form
gbt_neg_line_profile
gbt_neg_udp_carrier
gbt_neg_port_undeclared
gbt_neg_address_family
gbt_neg_http_method_get
gbt_neg_error_propagation
```

## 9. 修订记录

- v1.0.0（2026-08-21）：旧稿首版（20 = 14 正 + 6 负，未过审查）。
- v2.0.0（2026-09-02，v1.3 重写级修复轮）：独立审查（rr-gbt，CRITICAL 6 + MAJOR 10 + MINOR 4，行为面 114 点）后整对重写，20 → **81 例（53 正 + 28 负）**。关键更正与扩量：**G-4/G-5** 主层链 [ip,tcp,http,gbt]（复用 http 层）；**G-6** jsonrpc-line 删除 + 归口负例 76；**G-11** longpoll 真实语义（longpolluri 正例 30/独立请求 31/参数 32）；**G-12/G-13** Basic 默认（4）+ 401（5）+ 500（6/38）三态；**G-15/G-16** workid（33/34 + 负例 66）；**G-14** BIP 9/145/coinbasetxn 边界 + 归口负例 73-75；**G-19** 全部叙述式断言作废 → 实测基线（§1）+ hex 基线（§3）+ 包数算式；**G-9** 负例 28 行原子 + wire_fault 三方同序；**G-7** concurrent（46）+ multi_flow 作废；**G-8** 契约段 + #14 删除；**G-10** 18332（3）；**G-3/G-17/G-18** 模板 18 键逐字段 + mutable 定义值 + 动态值两类；**G-20** ID 权威 = 本文 §2 + §8 块 + notes 同步项（§7.2）+ 协议事实哨兵（§7.5）；error_propagation 保留可构造式（81，v1.3 §4 L79 + 13 对判例）。待复验关闭。

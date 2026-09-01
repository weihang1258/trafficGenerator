# GetWork（Bitcoin legacy 工作获取 RPC）测试用例契约

> 版本：v2.0.0（测试用例）
> 日期：2026-09-02
> 配套设计：`docs/protocol-designs/76-getwork-design.md`（v2.0.0）
> 机器契约：`trafficgen/test/protocol_pcap/cases/getwork.json`（proto key：`getwork`；本版不写文件，当前 JSON 仅含注册前置占位）
> 状态：按《协议设计文档与用例文档需求文档 v1.3》重写级修复轮产物：20 → **62 例（45 正 + 17 负）**，待复验关闭。

## 1. 测试原则和未注册边界

用例从设计 §2–§8 逐项派生，按 v1.3 行为面全枚举扩量，共 **62 个唯一语义 ID：45 个正例 + 17 个负例**（对应审查枚举 ~90 行为面点）。派生规则：设计 §3.1 每个交互行、§3.2 每个消息形态、§3.3 每个字段约束、§3.4 每条公式、§5 每条会话/终止口径、§7 每行错误处理（逐故障输入）在本文有对应断言；断言不得超出设计声明范围。**一个用例只验证一个协议行为**（v1.3 §7 原子原则）。

**TSHARK 实测基线（本机 3.6.14，2026-09-01，构造 pcap 实证 /tmp/getwork_v13/gw.pcap，非臆造）**：
1. 本机**无 getwork 专用 dissector**（`tshark -G protocols | grep -i getwork` 为空）；断言不依赖 getwork.* 字段。
2. **8332 端口 HTTP POST 无需 decode-as 即自动解出**（启发式命中，Protocol 列 `HTTP/JSON`）；80 同；9332 非默认端口按本基线同样免 DecodeAs——若未来版本启发式行为变化，实现期按实测补 `-d tcp.port==N,http` 并在此登记版本口径。
3. 可用断言字段：`http.request.method`/`http.response.code`/`http.content_length`/`http.file_data`/`http.connection`/`http.authorization`；**`Content-Type: application/json` 触发 JSON 子解析**——`json.key`/`json.value.string`/`json.value.boolean`/`json.path` 可直接断到 `/method`、`/result/data`、`/result/hash1`、`/error/code` 级（`json.value.string=="getwork"` 可过滤）。**断言通道 = http.* + json.* 双通道，tcp.payload 原始 hex 兜底**（v1.0.0 "只有 raw payload" 低估作废）。
4. 偏移：无 VLAN/options 时 HTTP 起行 IPv4 offset 54 / IPv6 74；JSON body 起点 = 54/74 + 固定头集合字节长（§3 基线可预算）。

**pcap/NIC 双输出契约（G-5）**：pcap 与 `port_group`/NIC 两种输出路径使用同一份用例契约——同一组语义 ID、同一包数约定、同一断言集（http.*/json.*/frames），不含输出路径专有断言（与 64-cwmp/66-doh/75-stratum 同形）。

当前 JSON 只保留一个 `getwork_neg_unregistered` 注册前置占位：`proto=getwork`、`expect_error=true`、`error_contains` 精确为 `unknown layer`；该占位不计入 62 个语义 ID，不得把拒绝、0 包或空 PCAP 报告为 GetWork 行为通过。注册后移除占位，按本文 §2（45 正例）+ §5（17 负例）顺序补入。

## 2. 原子用例索引

| # | ID | 类型 | 覆盖（设计 §） | 约定 packet_count |
|---:|---|---|---|---:|
| 1 | `getwork_request_ipv4_8332` | 正 | §1/§2：IPv4/TCP/HTTP 8332 基线事务（申请→work，id 配对）；Wiki getwork | 9 |
| 2 | `getwork_request_ipv6_8332` | 正 | §2：IPv6 fixture（ipv6.nxt=6、offset 74）、地址族隔离 | 9 |
| 3 | `getwork_port80` | 正 | §2：80 端口 HTTP 载体正例 | 9 |
| 4 | `getwork_port_nondefault_9332` | 正 | §2：非默认端口 9332 显式声明（免 DecodeAs 实测基线） | 9 |
| 5 | `getwork_uri_variant` | 正 | §3.1：URI `/rpc` 显式端点、Host 同步 | 9 |
| 6 | `getwork_auth_basic_header` | 正 | §1/§3.1：Authorization: Basic dXNlcjpwYXNz 在场（现网默认形态） | 9 |
| 7 | `getwork_http401_noauth` | 正 | §3.1：无凭证请求 → 401 + WWW-Authenticate、空 body（观测形态） | 9 |
| 8 | `getwork_http500_rpc_error` | 正 | §3.1：HTTP 500 + error 对象（code/message）、请求 id 保留 | 9 |
| 9 | `getwork_jsonrpc10_default` | 正 | §3.2：1.0 形态（无 jsonrpc 成员，json.key 不含） | 9 |
| 10 | `getwork_jsonrpc20_form` | 正 | §3.2：2.0 观测形态（jsonrpc 成员前置） | 9 |
| 11 | `getwork_http10_close` | 正 | §3.1：HTTP/1.0 + Connection: close + 单事务后 FIN | 9 |
| 12 | `getwork_host_header_value` | 正 | §3.1：Host 头精确值 `<dst_ip>:<port>` | 9 |
| 13 | `getwork_id_numeric_sequence` | 正 | §3.2/§5：keep-alive 三事务 id 1/2/3 递增配对 | 13 |
| 14 | `getwork_id_string_form` | 正 | §3.2：字符串 id `"rpc-001"` 形态 | 9 |
| 15 | `getwork_id_large_value` | 正 | §3.2：边界大数值 id（2147483647） | 9 |
| 16 | `getwork_empty_params_form` | 正 | §3.2：申请 params 恰 `[]`（json.path=/params 空数组） | 9 |
| 17 | `getwork_work_data_length` | 正 | §3.3：data 恰 256 hex（G-1 口径） | 9 |
| 18 | `getwork_work_target_length` | 正 | §3.3：target 恰 64 hex | 9 |
| 19 | `getwork_work_midstate_length` | 正 | §3.3：midstate 恰 64 hex | 9 |
| 20 | `getwork_work_hash1_constant` | 正 | §3.3/§3.4：hash1 恰 128 hex 且等于 legacy 常量 | 9 |
| 21 | `getwork_work_hex_charset` | 正 | §3.3：四字段恒 `[0-9a-f]` 小写 | 9 |
| 22 | `getwork_work_no_jobid` | 正 | §3.3：标准 result 恰 4 键、无 job_id（json.key 计数） | 9 |
| 23 | `getwork_jsonpath_result_data` | 正 | §1 实测基线③：json.path=/result/data 断言通道 | 9 |
| 24 | `getwork_target_boundary` | 正 | §3.4：边界 target fixture（前 8 hex 后全零） | 9 |
| 25 | `getwork_error_null_success` | 正 | §3.2：成功响应 error 恰 null（三元组形状） | 9 |
| 26 | `getwork_submit_accepted` | 正 | §3.5：getwork(data) 提交 → result:true | 11 |
| 27 | `getwork_submit_rejected_false` | 正 | §3.5：result:false 合法拒绝（非 planner 错误） | 11 |
| 28 | `getwork_submit_result_object` | 正 | §3.5：对象结果三态 {status,share_id} | 11 |
| 29 | `getwork_submit_single_param` | 正 | §3.2：提交 params 恰单元素（G-2，无第二参） | 11 |
| 30 | `getwork_nonce_in_data` | 正 | §3.3：提交 data 前 152 hex same_as_packet、仅 nonce 位变 | 11 |
| 31 | `getwork_cycle_repeat` | 正 | §4②：getwork→submit→getwork→submit 四事务循环 | 15 |
| 32 | `getwork_new_work_distinct` | 正 | §5：两次申请 data distinct（每请求新 work） | 11 |
| 33 | `getwork_keepalive_multi_transaction` | 正 | §5：keep-alive 三事务、Connection 恒 keep-alive、按 CL 分界 | 13 |
| 34 | `getwork_keepalive_then_close` | 正 | §3.1/§5：复用两事务后末响应 Connection: close + FIN | 11 |
| 35 | `getwork_body_mss_spanning` | 正 | §5：三事务响应打包 1770B 跨 MSS、按 tcp.stream 重组 | 10 |
| 36 | `getwork_multi_body_single_segment` | 正 | §5：两事务请求/响应各粘单段、按 CL 拆分 | 9 |
| 37 | `getwork_multi_session` | 正 | §5：双会话按序展开（第二会话包号 = 前会话+1） | 18 |
| 38 | `getwork_concurrent_sessions` | 正 | §5：concurrent:true 双会话交织（tcp.stream distinct、id/work 不串） | 18 |
| 39 | `getwork_session_state_isolation` | 正 | §5：双会话各两事务、最近 work/id 互不串用 | 22 |
| 40 | `getwork_retry_after_500` | 正 | §5：同连接 500 后重试（新 id）、成功后正常事务 | 11 |
| 41 | `getwork_reconnect_new_stream` | 正 | §5：干净关闭后新四元组新连接（tcp.stream distinct、新 work） | 18 |
| 42 | `getwork_rst_interrupt` | 正 | §5：RST 中断（tcp.flags.reset=1、无 FIN、其后无 body 帧） | 5 |
| 43 | `getwork_no_frames_after_fin` | 正 | §5：FIN×2 挥手后无新业务帧、全流无 RST | 9 |
| 44 | `getwork_dual_family` | 正 | §4：v4+v6 双会话并行、各族地址/端口独立 | 18 |
| 45 | `getwork_pcap_nic_consistency` | 正 | §1 输出契约：pcap/NIC 双捕获同断言（一致性专项） | 13 |
| 46 | `getwork_neg_bad_json` | 负 | §7：body 非合法 JSON | — |
| 47 | `getwork_neg_body_truncated` | 负 | §7：body 截断 | — |
| 48 | `getwork_neg_content_length_mismatch` | 负 | §7：Content-Length 不符 | — |
| 49 | `getwork_neg_unknown_method` | 负 | §7：未知 method（getblocktemplate 归口） | — |
| 50 | `getwork_neg_getwork_params_nonempty` | 负 | §7：申请 params 非空 | — |
| 51 | `getwork_neg_submit_two_params` | 负 | §7：提交双参数 | — |
| 52 | `getwork_neg_data_not_hex` | 负 | §7：data 非十六进制 | — |
| 53 | `getwork_neg_data_length` | 负 | §7：data 长度错 | — |
| 54 | `getwork_neg_field_missing` | 负 | §7：work 缺 hash1 | — |
| 55 | `getwork_neg_submit_work_uncorrelated` | 负 | §7：提交 data 与会话 work 无关联 | — |
| 56 | `getwork_neg_id_mismatch` | 负 | §7：响应 id 错配 | — |
| 57 | `getwork_neg_cross_session_work` | 负 | §7：跨会话消费 work | — |
| 58 | `getwork_neg_udp_carrier` | 负 | §7：UDP 载体 | — |
| 59 | `getwork_neg_port_undeclared` | 负 | §7：端口未声明 | — |
| 60 | `getwork_neg_address_family` | 负 | §7：地址族/层链冲突 | — |
| 61 | `getwork_neg_http_method_get` | 负 | §7：GET 方法承载 | — |
| 62 | `getwork_neg_error_propagation` | 负 | §7：错误被吞假成功 | — |

**包数约定**（设计 §5）：单事务 = 3+2+4 = 9；keep-alive N 事务 = 7+2N；MSS 跨段/粘连按实际段数；RST = 5；重连/多会话 = Σ连接；双输出例 = 3 事务 = 13。

## 3. 线上编码和偏移断言

**fixture 常量**（设计 §3.4 同源）：IPv4 `192.0.2.76:4076 → 198.51.100.76:8332`；IPv6 `2001:db8::76 → 2001:db8:100:76`；非默认 9332；`data_work = 00000020 11×32 22×32 66dead00 1b0404cb 00000000(nonce) 00×48`（256 hex）；`data_submit` 仅 nonce 位 `2f9f2e1d`；`target = 00000000ffff` + `00`×26（12+52 = 64 hex）；`midstate = 33`×32；`hash1 = 00000080` + `00`×56 + `80020000`；auth `dXNlcjpwYXNz`；id 1/2/3、`"rpc-001"`、`2147483647`。

**核心行字节基线**（hex 大写；CRLF=`0D0A`）：

| 消息 | 全长 | hex |
|---|---:|---|
| 基线请求（头+body，含 Authorization） | 195 | 头 `504F5354202F20485454502F312E310D0A486F73743A203139382E35312E3130302E37363A383333320D0A417574686F72697A6174696F6E3A20426173696320` + …（Content-Type/CL=39/Connection 三头）+ 尾 `2C226D6574686F64223A22676574776F726B222C22706172616D73223A5B5D7D` |
| 基线 work 响应（头+body） | 687 | 头 `485454502F312E3120323030204F4B0D0A436F6E74656E742D547970653A206170706C69636174696F6E2F6A736F6E0D0A436F6E74656E742D4C656E6774683A` + `3539310D0A…`（CL=591）+ 尾 `303830303230303030227D2C226572726F72223A6E756C6C2C226964223A317D` |
| 申请请求 body（1.0，id=1） | 39 | `7B226964223A312C226D6574686F64223A22676574776F726B222C22706172616D73223A5B5D7D` |
| 提交请求 body（id=2，params=[data_submit]） | 297 | `7B226964223A322C226D6574686F64223A22676574776F726B222C22706172616D73223A5B22` + data_submit 512 hex + `225D7D` |
| 布尔响应 body（true，id=2） | 35 | `7B22726573756C74223A747275652C226572726F72223A6E756C6C2C226964223A327D` |
| 布尔响应 body（false，id=2） | 36 | `7B22726573756C74223A66616C73652C226572726F72223A6E756C6C2C226964223A327D` |
| 500 错误响应 body（id=3） | 75 | `7B22726573756C74223A6E756C6C2C226572726F72223A7B22636F6465223A2D33323630312C226D657373616765223A226D6574686F64206E6F7420666F756E64227D2C226964223A337D` |

断言分层：①载体与方向——设备帧 `tcp.srcport=4076`、`tcp.dstport=8332`（变体 80/9332）、`ip.version=4`/`ipv6.nxt=6`、`tcp.len` 按段；②HTTP——`http.request.method=POST`、`http.response.code∈{200,401,500}`、`http.content_length` 精确值、`http.authorization="Basic dXNlcjpwYXNz"`（§1 实测字段）；③JSON——`json.path=/method`、`json.value.string="getwork"`、`json.path=/result/data` + 值长度 256、`json.path=/error/code` 等；④frames hex——短消息全 hex、长消息前缀+后缀（§3 表）；⑤重组——跨段/粘连按 `tcp.stream` 重组后断整消息。

## 4. 正例逐项断言契约

1. **`getwork_request_ipv4_8332`**（9 = 3+2+4）：帧 4 请求（offset 54 起）——`http.request.method=POST`、`http.file_data` = 基线 body 39B、Content-Length=39、id 配对（json.path=/id 与响应同值）；帧 5 响应 `http.response.code=200`、CL=591。
2. **`getwork_request_ipv6_8332`**（9）：同 1 断言集 + `ipv6.nxt=6`、HTTP 起行 offset 74、fixture 地址 `2001:db8::76→2001:db8:100:76`、不出现 v4 地址。
3. **`getwork_port80`**（9）：`tcp.dstport=80`、Host `198.51.100.76:80`、其余同 1——端口只作载体，不作唯一识别。
4. **`getwork_port_nondefault_9332`**（9）：`tcp.dstport=9332`（配置显式声明）、免 DecodeAs 断言集与 1 全同（§1 基线②）。
5. **`getwork_uri_variant`**（9）：请求行 `POST /rpc HTTP/1.1`、Host 同步——断言 `http.request.uri=/rpc` 等值与 frames hex 请求行区 `504F5354202F72706320`。
6. **`getwork_auth_basic_header`**（9）：`http.authorization="Basic dXNlcjpwYXNz"`、frames hex 头区含 `417574686F72697A6174696F6E3A2042617369632064584E6C636A707759584E7A`。
7. **`getwork_http401_noauth`**（9）：请求无 Authorization 头（frames hex 不含该头区）；响应 `http.response.code=401`、含 `WWW-Authenticate: Basic realm="jsonrpc"`、`http.content_length=0`、无 JSON body。
8. **`getwork_http500_rpc_error`**（9）：响应 `http.response.code=500`、body = 75B 错误对象全 hex（§3 表）、`json.path=/error/code` 值 −32601、`json.path=/id` 保留请求 id=3、`json.path=/result` 值 null。
9. **`getwork_jsonrpc10_default`**（9）：请求 body 39B 全 hex；**断言 json.key 集合不含 `jsonrpc`**（1.0 形态无版本成员——G-16）。
10. **`getwork_jsonrpc20_form`**（9）：请求 body 前置 `{"jsonrpc":"2.0"`（frames hex 头区 `7B226A736F6E727063223A22322E3022`）、body 55B、响应同形。
11. **`getwork_http10_close`**（9）：请求行 `HTTP/1.0`、无 Host 头、无 Authorization 可选；响应 `Connection: close`；单事务后即 FIN×2（无第二事务）。
12. **`getwork_host_header_value`**（9）：frames hex 头区 `486F73743A203139382E35312E3130302E37363A38333332`（Host: 198.51.100.76:8332）精确在场。
13. **`getwork_id_numeric_sequence`**（13 = 7+2×3）：keep-alive 三申请事务，`json.path=/id` 三帧递增 1/2/3、响应与请求同值配对、无错配。
14. **`getwork_id_string_form`**（9）：id=`"rpc-001"`（json 值为字符串类型）、请求 47B / 响应 id 同串。
15. **`getwork_id_large_value`**（9）：id=2147483647（10 位边界值）、body 长度按公式 38+10=48。
16. **`getwork_empty_params_form`**（9）：`json.path=/params` 值恰空数组（frames hex 尾区 `22706172616D73223A5B5D7D`）。
17. **`getwork_work_data_length`**（9）：`json.path=/result/data` 值长度恰 256 hex 字符（G-1）；**不断言 128**（旧稿口径作废）。
18. **`getwork_work_target_length`**（9）：`json.path=/result/target` 值长度恰 64。
19. **`getwork_work_midstate_length`**（9）：`json.path=/result/midstate` 值长度恰 64。
20. **`getwork_work_hash1_constant`**（9）：`json.path=/result/hash1` 值长度 128 **且逐字符等于 legacy 常量**（00000080+00×56+80020000——frames hex 尾区 `303830303230303030227D`）。
21. **`getwork_work_hex_charset`**（9）：四字段值全部匹配 `[0-9a-f]{64,256}`（小写十六进制，无大写/非 hex 字符）。
22. **`getwork_work_no_jobid`**（9）：result 对象 json.key 集合恰 {data,target,midstate,hash1} 四键、**不含 job_id**（G-2：标准接口无此字段）。
23. **`getwork_jsonpath_result_data`**（9）：断言通道专项——`json.path=/result/data` 存在且值 = fixture data_work 前 32 hex 前缀（`00000020111111111111111111111111`）。
24. **`getwork_target_boundary`**（9）：target 前 12 hex=`00000000ffff`、后 52 hex 全 `00`（边界 fixture 逐字符断言）。
25. **`getwork_error_null_success`**（9）：成功 work 响应 `json.path=/error` 值恰 null（1.0 三元组 result/error/id 形状完整）。
26. **`getwork_submit_accepted`**（11 = 3+4+4）：帧 4 申请、帧 5 work、帧 6 提交（body 297B、params 单元素）、帧 7 响应 body 35B 全 hex、`json.value.boolean=true`。
27. **`getwork_submit_rejected_false`**（11）：提交合法但响应 `json.value.boolean=false`（36B 全 hex）——**rejected 是正例形态，非 planner 错误**。
28. **`getwork_submit_result_object`**（11）：响应 result 为对象 {status:"accepted",share_id:"sh-0001"}（73B）——第三态。
29. **`getwork_submit_single_param`**（11）：提交 `json.path=/params` 数组长度恰 1（G-2：无第二参数、方法名仍 getwork——frames hex 含 `226D6574686F64223A22676574776F726B22`）。
30. **`getwork_nonce_in_data`**（11）：提交 data 前 152 hex 与最近 work data `same_as_packet`、第 153-160 hex = `2f9f2e1d`、其余填充同——nonce 位关联。
31. **`getwork_cycle_repeat`**（15 = 7+2×4）：getwork→submit→getwork→submit 四事务，id 1/2/3/4 递增、四次 CL 交替 39/591/297/35、每事务边界清晰。
32. **`getwork_new_work_distinct`**（11）：两次申请的 data `distinct`（第二次 work fixture data 第 8-12 hex 变体）、target/midstate 同 fixture。
33. **`getwork_keepalive_multi_transaction`**（13 = 7+2×3）：三事务全响应 `http.connection=keep-alive`、无中间 FIN、按 Content-Length 拆三对请求/响应、id 各配对。
34. **`getwork_keepalive_then_close`**（11 = 7+2×2）：前两事务 keep-alive、末响应 `http.connection=close`、随后 FIN×2（无第三事务）。
35. **`getwork_body_mss_spanning`**（10 = 3+1+2+4）：三申请请求粘单段（3×39=117B 一段）、三响应打包 3×591=1773B 跨两段（MSS 1460）——按 `tcp.stream` 重组后逐响应断 CL=591 与 json.path=/id 递增；单段不得断整消息。
36. **`getwork_multi_body_single_segment`**（9 = 3+1+1+4）：两事务请求粘一段（2×39=78B）、响应粘一段（591+35=626B）——按 CL 边界拆分后各断言；段边界 ≠ 消息边界双向断言。
37. **`getwork_multi_session`**（18 = 9+9）：会话 1（src_port 4076）整块先跑、会话 2（src_port 4077）后跑；**会话 2 握手包号 = 10**（= 前会话 9 包+1）、`tcp.stream` 两值 distinct、各会话 id 序列独立。
38. **`getwork_concurrent_sessions`**（18 = 9+9）：`concurrent: true` 双会话**交织**（判例 cwmp⑦/doh#24/onvif#56/hl7#26/megaco#45/bacnet#47）——两 `tcp.stream` distinct、帧序交织（会话 2 首帧先于会话 1 FIN）、各会话内请求/响应/id 配对完整不放宽、work/id 跨流不串。
39. **`getwork_session_state_isolation`**（22 = 11+11）：两会话各两事务（申请+提交）；会话 2 的提交 data 引用会话 2 自己的 work（nonce 关联本流）、两流 id 序列同值 1/2 但不跨流配对。
40. **`getwork_retry_after_500`**（11 = 3+2+2+4）：同连接：请求 id=3 → 响应 500（75B 错误对象）→ 重试请求 id=4 → 响应 200 work——重试请求为**新 id 新 body**、500 后无 FIN（连接未断）。
41. **`getwork_reconnect_new_stream`**（18 = 9+9）：连接 1 单事务干净 FIN 关闭；连接 2 新四元组（src_port 4078）新 work 上下文（data 第 8-12 hex 再变体）——`tcp.stream` 两值 distinct、连接 2 首句从握手起。
42. **`getwork_rst_interrupt`**（5 = 3+1+1）：握手 3 + 请求 1 + **RST 1**（`tcp.flags.reset=1`）——无响应 body 帧、无 FIN 挥手、流到此终止（G-9）。
43. **`getwork_no_frames_after_fin`**（9）：单事务 + FIN×2 挥手——断言包数恰 9、末帧后无 `tcp.len>0` 帧、全流无 RST。
44. **`getwork_dual_family`**（18 = 9+9）：v4 会话（192.0.2.76→198.51.100.76）+ v6 会话（2001:db8::76→2001:db8:100:76）各单事务——`ip.version` 各 4/6、v6 断 `ipv6.nxt=6` 不出现 v4 地址、两流状态独立。
45. **`getwork_pcap_nic_consistency`**（13 = 7+2×3）：同一三事务 fixture 双输出——pcap 与 NIC 捕获（tcpdump enp135s0f0np0）各断言同一集合：三对请求/响应、CL 精确值、id 1/2/3、data 前缀；checksum offload 差异不影响（断言不含校验和字段）。

## 5. 负例契约

每个负例必须在 planner/validator 阶段失败并传播为 task error（任务错误），不得产生成功 PCAP、`completed/0 packet` 或只剩 TCP/HTTP 外壳的假成功。执行期 `expect` 键集合严格为 `{"expect_error", "error_contains"}`。**逐故障输入原子拆分：一行一例，钉死单一 `wire_fault`；主锚词钉死单一字面值（备选括注）**，与设计 §7 表逐行同序同词（17 行）：

| # | ID | `wire_fault` | 故障输入（单一注入） | 主锚词（备选） |
|---:|---|---|---|---|
| 46 | `getwork_neg_bad_json` | `bad_json` | 声明的 body 序列化后非合法 JSON（如手写 body 少闭括号） | `json` |
| 47 | `getwork_neg_body_truncated` | `body_truncated` | body 截断（Content-Length 声明值大于实际内容） | `truncat`（body） |
| 48 | `getwork_neg_content_length_mismatch` | `content_length_mismatch` | Content-Length ≠ 实际 body 字节数 | `content-length` |
| 49 | `getwork_neg_unknown_method` | `unknown_method` | method 取支持集外值（如 `getblocktemplate`——BIP 22 边界归口） | `method`（unknown） |
| 50 | `getwork_neg_getwork_params_nonempty` | `getwork_params_nonempty` | 申请请求 params 非空数组（如 `[data]`） | `params`（getwork） |
| 51 | `getwork_neg_submit_two_params` | `submit_two_params` | 提交请求 params 为两元素（如 `[data, flag]`） | `params`（submit） |
| 52 | `getwork_neg_data_not_hex` | `data_not_hex` | data 含非十六进制字符（如插入 `zz`） | `hex` |
| 53 | `getwork_neg_data_length` | `data_length` | data 长度 ≠ 256 hex（如 254/258） | `length`（data） |
| 54 | `getwork_neg_field_missing` | `field_missing` | work 对象缺任一必选字段（注入 hash1 缺失） | `hash1`（missing） |
| 55 | `getwork_neg_submit_work_uncorrelated` | `submit_work_uncorrelated` | 提交的 data 与本会话最近 work 无 nonce 关联（前 152 hex 不一致） | `correlation`（work） |
| 56 | `getwork_neg_id_mismatch` | `id_mismatch` | 响应 id 与请求 id 不一致（如请求 1 响应 9） | `id`（mismatch） |
| 57 | `getwork_neg_cross_session_work` | `cross_session_work` | 会话 B 的提交引用会话 A 的 work data | `session`（cross） |
| 58 | `getwork_neg_udp_carrier` | `udp_carrier` | UDP 载体承载 getwork（仅 TCP 上的 HTTP 合法） | `carrier`（udp） |
| 59 | `getwork_neg_port_undeclared` | `port_undeclared` | 非 8332/80 端口未显式声明（如 9443 静默使用） | `port`（undeclared） |
| 60 | `getwork_neg_address_family` | `address_family` | IPv6 地址配 IPv4 层链（或反向） | `family`（address） |
| 61 | `getwork_neg_http_method_get` | `http_method_get` | GET 方法承载 getwork 请求（必须 POST） | `post`（method） |
| 62 | `getwork_neg_error_propagation` | `error_propagation` | validator 已知错误被吞、任务 completed/0 packet 假成功 | `propagat`（error） |

**不得误报**（设计 §7 同款）：result:false（正例 27）、HTTP 500（8）、401（7）、HTTP/1.0（11）、2.0 形态（10）、无 job_id（22）、字符串 id（14）、非 `/` URI（5）均为合法形态。

## 6. 五层覆盖映射

| 层 | 用例 |
|---|---|
| 功能层 | 1-16（载体/形态/id）、26-32（提交三态）、46-62（负例逐故障） |
| 性能层 | 35（MSS 跨段）、36（粘连拆分）、33（多事务） |
| 数据场景层 | 17-25（work 字段宽度/字符集/边界/形状）、30（nonce 位关联） |
| 地址与流层 | 2/44（IPv6/双栈）、3/4（80/9332）、37-39（多会话/并发/隔离）、40-43（重试/重连/RST/FIN） |
| 业务层 | 31（挖掘循环）、41（断流重连）、45（双输出） |

## 7. 机器契约与静态检查

1. `python3 -m json.tool trafficgen/test/protocol_pcap/cases/getwork.json` 通过；当前数组恰含 1 条 `getwork_neg_unregistered`：`proto=getwork`、`expect_error=true`、`error_contains` 精确为 `unknown layer`。
2. **注册同步项（G-17）**：注册替换占位时同步修正 JSON 占位期陈旧 notes（"14 positive and 6 negative"旧稿统计）为本文 §2 各行覆盖描述——占位期不改 JSON，登记为注册时必做项。
3. 正例断言键集：`fields`（http.*/json.*）+ `frames`（hex 前/后缀或全量）+ `min_packets`；负例键集恰 `{expect_error, error_contains}`。
4. 三方一致性：设计 §6 wire_fault 枚举 17 值 = 设计 §7 表 17 行 = 本文 §5 表 17 行，同序同词；ID 权威 = 本文 §2（设计 §9 簇级图景）。
5. **协议事实哨兵（G-1/G-2 回归防护）**：任何文档/断言出现 "128 hex"（对 data）、"`submit`" 方法名（ID 命名除外）、"64-byte data" 即为回归错误——本检查项钉死 v2.0.0 更正不被回退。

## 8. 三方一致性表

设计 §9（ID 权威声明）、本文 §2（#1–#45 正例）+ §5（#46–#62 负例）、实现后 `getwork.json` 保持同一 62 个语义 ID、同一顺序（当前 JSON 另有占位，不计入）：

```text
getwork_request_ipv4_8332
getwork_request_ipv6_8332
getwork_port80
getwork_port_nondefault_9332
getwork_uri_variant
getwork_auth_basic_header
getwork_http401_noauth
getwork_http500_rpc_error
getwork_jsonrpc10_default
getwork_jsonrpc20_form
getwork_http10_close
getwork_host_header_value
getwork_id_numeric_sequence
getwork_id_string_form
getwork_id_large_value
getwork_empty_params_form
getwork_work_data_length
getwork_work_target_length
getwork_work_midstate_length
getwork_work_hash1_constant
getwork_work_hex_charset
getwork_work_no_jobid
getwork_jsonpath_result_data
getwork_target_boundary
getwork_error_null_success
getwork_submit_accepted
getwork_submit_rejected_false
getwork_submit_result_object
getwork_submit_single_param
getwork_nonce_in_data
getwork_cycle_repeat
getwork_new_work_distinct
getwork_keepalive_multi_transaction
getwork_keepalive_then_close
getwork_body_mss_spanning
getwork_multi_body_single_segment
getwork_multi_session
getwork_concurrent_sessions
getwork_session_state_isolation
getwork_retry_after_500
getwork_reconnect_new_stream
getwork_rst_interrupt
getwork_no_frames_after_fin
getwork_dual_family
getwork_pcap_nic_consistency
getwork_neg_bad_json
getwork_neg_body_truncated
getwork_neg_content_length_mismatch
getwork_neg_unknown_method
getwork_neg_getwork_params_nonempty
getwork_neg_submit_two_params
getwork_neg_data_not_hex
getwork_neg_data_length
getwork_neg_field_missing
getwork_neg_submit_work_uncorrelated
getwork_neg_id_mismatch
getwork_neg_cross_session_work
getwork_neg_udp_carrier
getwork_neg_port_undeclared
getwork_neg_address_family
getwork_neg_http_method_get
getwork_neg_error_propagation
```

## 9. 修订记录

- v1.0.0（2026-08-21）：旧稿首版（20 = 14 正 + 6 负，未过审查）。
- v2.0.0（2026-09-02，v1.3 重写级修复轮）：独立审查（docs-bacnet，17 findings = C7/D7/N3，~90 行为面点）后整对重写，20 → **62 例（45 正 + 17 负）**。关键更正与扩量：**G-1** data 恰 256 hex（正例 17）；**G-2** 提交 = getwork(data) 单参（正例 29）、job_id 声明作废（正例 22 断无）；**G-3** Basic 头默认（6）+ 401（7）+ 500（8）三态；**G-8** 实测基线（json.* 双通道，§1）+ 9332（4）；**G-6/G-7** 负例 17 行原子 + wire_fault 三方同序（§5）；**G-12/G-13** fixture 全量钉死 + 包数约定（§3/§2）；**G-14** 依据列 + ID 权威 = 本文 §2（§8）；**G-16** 1.0 默认（9）+ 2.0 观测（10）+ HTTP/1.0（11）；**G-15** BIP22/longpoll/TLS/chunked 边界（设计 §1/§8）；**G-17** JSON notes 同步项（§7.2）；**协议事实哨兵**（§7.5）。待复验关闭。

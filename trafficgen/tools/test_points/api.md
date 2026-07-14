# REST API 层测试点细化

> 测试基础设施（所有 SIMULATED 点共用）: `httptest.NewRecorder()`/`httptest.NewServer` + 内存 SQLite (`glebarez/sqlite`) + `storage.AutoMigrate` + `storage.DB{DB:gormDB}`。鉴权上下文用 `r.Use(func(c){c.Set("userID",...);c.Set("username",...);c.Set("roles",...);c.Next()})` 注入（绕过中间件测 handler），或挂真实 `auth.AuthMiddlewareWithDB` 测中间件。引擎依赖（`TaskHandler.engine *core.Engine`）需用 mock Engine 接口（建议把 `engine` 抽成 interface）或用真实未启动/已启动 `core.NewEngine` + pcap 输出到 `t.TempDir()`。所有断言精确到 HTTP status + body JSON `code`/`message`/`data` 字段值。
>
> 约定: body 标准响应 `{code,message,data}`。`code=0` 表业务成功（HTTP 200/201）。错误 `code` == HTTP status。断言写“status=X; body.code=Y; body.message 含 Z; body.data.k=W”。

## 组件: 纯函数/工具 (auth_handler.go/strategy_handler.go/port_group_handler.go/task_handler.go/pcap_handler.go)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| HASH-POS | hashToken 确定性 | TestHashToken_Deterministic | "secret-token" | 两次调用返回相同 64 字符 hex；等于 sha256("secret-token") | REAL | 直接调 `hashToken` |
| HASH-BR1 | hashToken 空串 | TestHashToken_Empty | "" | 返回 sha256("") 的已知 hex | REAL | |
| HASH-BR2 | hashToken 不同输入不同输出 | TestHashToken_Distinct | "a","b" | 两个 hash 不同 | REAL | |
| VALIP-POS1 | validateIP 合法 IPv4 | TestValidateIP_Valid | "10.0.0.1" | true | REAL | |
| VALIP-POS2 | validateIP 边界 IPv4 | TestValidateIP_Broadcast | "255.255.255.255" | true | REAL | |
| VALIP-NEG1 | validateIP 拒 IPv6 | TestValidateIP_IPv6 | "2001:db8::1" | false（正则要求点分四段） | REAL | 记录: IPv6 被拒（设计如此） |
| VALIP-NEG2 | validateIP 段超 255 | TestValidateIP_OutOfRange | "999.1.1.1" | false | REAL | |
| VALIP-NEG3 | validateIP 段不足 | TestValidateIP_ThreeOctets | "10.0.0" | false | REAL | |
| VALIP-NEG4 | validateIP 空串 | TestValidateIP_Empty | "" | false | REAL | |
| VALIP-NEG5 | validateIP 五段 | TestValidateIP_FiveOctets | "10.0.0.0.1" | false | REAL | |
| VALMAC-POS1 | validateMAC 小写 | TestValidateMAC_Lower | "aa:bb:cc:dd:ee:ff" | true | REAL | |
| VALMAC-POS2 | validateMAC 大写 | TestValidateMAC_Upper | "AA:BB:CC:DD:EE:FF" | true | REAL | |
| VALMAC-NEG1 | validateMAC 横线分隔 | TestValidateMAC_Dash | "aa-bb-cc-dd-ee-ff" | false | REAL | |
| VALMAC-NEG2 | validateMAC 段不足 | TestValidateMAC_Short | "aa:bb:cc:dd:ee" | false | REAL | |
| VALMAC-NEG3 | validateMAC 非十六进制 | TestValidateMAC_NonHex | "zz:bb:cc:dd:ee:ff" | false | REAL | |
| VALMAC-NEG4 | validateMAC 空串 | TestValidateMAC_Empty | "" | false | REAL | |
| VCN-POS1 | validateConfigNetwork 全合法 | TestValidateConfigNetwork_AllValid | {src_ip:"10.0.0.1",dst_ip:"10.0.0.2",src_mac:"aa:..",dst_mac:"bb:.."} | 返回 "" | REAL | |
| VCN-POS2 | validateConfigNetwork 空配置 | TestValidateConfigNetwork_Empty | {} | 返回 "" | REAL | |
| VCN-POS3 | validateConfigNetwork 空串字段跳过 | TestValidateConfigNetwork_EmptyFields | {src_ip:""} | 返回 ""（s=="" 跳过） | REAL | |
| VCN-NEG1 | validateConfigNetwork 非法 src_ip | TestValidateConfigNetwork_BadSrcIP | {src_ip:"not-ip"} | 返回 "invalid IP format: src_ip = not-ip" | REAL | |
| VCN-NEG2 | validateConfigNetwork 非法 dst_ip | TestValidateConfigNetwork_BadDstIP | {dst_ip:"999.0.0.1"} | 返回 "invalid IP format: dst_ip = ..." | REAL | |
| VCN-NEG3 | validateConfigNetwork 非法 src_mac | TestValidateConfigNetwork_BadSrcMAC | {src_mac:"zz:zz:.."} | 返回 "invalid MAC format: src_mac = ..." | REAL | |
| VCN-NEG4 | validateConfigNetwork 非法 dst_mac | TestValidateConfigNetwork_BadDstMAC | {dst_mac:"aa"} | 返回 "invalid MAC format: dst_mac = ..." | REAL | |
| VCN-BR1 | validateConfigNetwork 非字符串 IP | TestValidateConfigNetwork_NonStringIP | {src_ip:12345} | 返回 ""（类型断言失败，跳过校验） | REAL | 记录: 数字型 IP 不被校验（潜在缺口） |
| VCN-BR2 | validateConfigNetwork IPv6 src_ip | TestValidateConfigNetwork_IPv6 | {src_ip:"2001:db8::1"} | 返回 "invalid IP format: src_ip = ..." | REAL | |
| CCH-POS | calculateConfigHash 确定性 | TestCalculateConfigHash_Deterministic | ("tcp","{...}","{...}") 两次 | 两次相同；改 protocol 后不同 | REAL | |
| CPCH-POS | calculatePortsConfigHash 确定性 | TestCalculatePortsConfigHash_Deterministic | 同一 ports JSON | 两次相同 | REAL | |
| CTH-POS | calculateTaskHash 不排序 | TestCalculateTaskHash_OrderMatters | ["a","b"] vs ["b","a"] 同 outputConfig | 两个 hash 不同（函数不排序） | REAL | 记录: 与 Create 内幂等检查（排序后）行为不同 |
| LLT-POS | layersLinkType 映射 | TestLayersLinkType_Ethernet | 1 | == layers.LinkTypeEthernet | REAL | |
| CT-POS | currentTime 近似 now | TestCurrentTime_Now | — | 返回值在 [now-1s, now+1s] | REAL | |
| RPP-POS1 | resolvePcapPath 绝对路径 | TestResolvePcapPath_Absolute | "/tmp/x.pcap"（t.TempDir 下） | 返回原值；父目录已创建 | SIMULATED | 用 t.TempDir 拼绝对路径 |
| RPP-POS2 | resolvePcapPath 相对路径 | TestResolvePcapPath_Relative | "x.pcap" | 返回 filepath.Join("pcap","x.pcap") | SIMULATED | |
| RPP-POS3 | resolvePcapPath 已带 pcap/ 前缀 | TestResolvePcapPath_AlreadyPrefixed | "pcap/x.pcap" | 返回 "pcap/x.pcap"（不重复前缀） | SIMULATED | |
| RPP-NEG1 | resolvePcapPath 空 | TestResolvePcapPath_Empty | "" | error "pcap_path is required" | SIMULATED | |
| RPP-NEG2 | resolvePcapPath Windows 风格 | TestResolvePcapPath_Windows | "C:\\path\\x.pcap" | error 含 "Windows-style path" | SIMULATED | |
| RPP-NEG3 | resolvePcapPath UNC | TestResolvePcapPath_UNC | "\\\\srv\\share\\x.pcap" | error 含 "UNC path" | SIMULATED | |
| RPP-BR1 | resolvePcapPath 自动建父目录 | TestResolvePcapPath_MkdirAll | "sub/dir/x.pcap"（t.TempDir 下绝对） | 返回路径；dir 存在 | SIMULATED | |
| RPP-NEG4 | resolvePcapPath 建目录失败 | TestResolvePcapPath_MkdirFail | 只读父目录下相对路径 | error 含 "failed to create directory" | SIMULATED | chmod 0500 父目录 |

## 组件: 鉴权中间件 (pkg/auth/middleware.go - AuthMiddlewareWithDB, M1-M8)

挂 `AuthMiddlewareWithDB(jwt, gdb)` + dummy handler 于 gin，用 httptest 打代表端点 `GET /api/v1/strategies`。M1-M8 在所有受保护端点共享，此处测一次逻辑；下面 MWGATE-* 参数化覆盖每个受保护端点。

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| MW-NEG1 | M1 无 Authorization 头 | TestAuthMW_NoHeader | 不带 Authorization | status 401; body.code=401; body.message="missing authorization header"; dummy handler 未执行 | SIMULATED | 设 c.Set 标志验证 handler 未跑 |
| MW-NEG2 | M2 非 Bearer 格式 | TestAuthMW_NotBearer | "Basic abc" | 401; "invalid authorization header format" | SIMULATED | |
| MW-NEG3 | M2 Bearer 无 token | TestAuthMW_BearerNoToken | "Bearer"（无空格 token） | 401; "invalid authorization header format" | SIMULATED | parts.SplitN 得 1 段 |
| MW-NEG4 | M3 畸形 JWT | TestAuthMW_MalformedJWT | "Bearer garbage" | 401; "invalid or expired token" | SIMULATED | |
| MW-NEG5 | M3 过期 JWT（签名合法） | TestAuthMW_ExpiredJWT | 用过期 JWTManager 签发 | 401; "invalid or expired token" | SIMULATED | JWTExpiresIn 设负值 |
| MW-NEG6 | M3 错密钥 JWT | TestAuthMW_WrongSecretJWT | 用 secret A 签，中间件用 secret B | 401; "invalid or expired token" | SIMULATED | |
| MW-NEG7 | M4 token 不在 DB | TestAuthMW_TokenNotInDB | 合法 JWT 但 DB 无该 token_hash | 401; "token not recognized" | SIMULATED | |
| MW-NEG8 | M5 DB 查询错 | TestAuthMW_DBError | 关闭/破坏 gdb 使 Scan 报错 | 500; "failed to validate token" | SIMULATED | 用坏连接或注入错误 |
| MW-NEG9 | M6 token 已 revoked | TestAuthMW_Revoked | DB token status="revoked" | 401; "token has been revoked" | SIMULATED | |
| MW-NEG10 | M7 token DB 过期 | TestAuthMW_DBExpired | DB ExpiresAt=now-1h | 401; "token has expired" | SIMULATED | |
| MW-POS | M8 全通过 | TestAuthMW_Valid | DB 有 active 未过期 token | 200; context userID/username/roles 正确注入; dummy handler 执行 | SIMULATED | |
| MWGATE-NOTOKEN | 每个受保护端点 无 token | TestProtectedEndpoints_NoToken | 参数化遍历所有 /api/v1/* 受保护端点，不发 Authorization | 每个均 401 "missing authorization header" | SIMULATED | 表驱动；端点清单见备注 |
| MWGATE-WRONGTOKEN | 每个受保护端点 错 token | TestProtectedEndpoints_WrongToken | 参数化 + "Bearer garbage" | 每个均 401 "invalid or expired token" | SIMULATED | |
| MWGATE-EXPIRED | 每个受保护端点 过期 token | TestProtectedEndpoints_ExpiredToken | 参数化 + 过期 JWT | 每个均 401 "invalid or expired token" | SIMULATED | |
| MWGATE-OTHERUSER-GLOBAL | 全局端点 他人 token 仍可用 | TestGlobalEndpoints_OtherUserToken | 用户 A token 访问 system/settings/port-group 端点 | 200（全局资源无用户隔离，by design） | SIMULATED | 覆盖 SYS1-3, settings, port-group list/get/create, interfaces |

> 受保护端点清单（MWGATE 参数化表）: GET/PUT/DELETE /api/v1/user/profile, POST /api/v1/auth/refresh, POST/GET/GET/:id/GET/:id/tasks/PUT/:id/DELETE/:id /api/v1/strategies, POST/POST/batch/GET/GET/:id/POST/:id/start/POST/:id/stop/DELETE/:id /api/v1/tasks, POST/DELETE/:id /api/v1/port-groups, GET /api/v1/system/{status,protocols,stats}, GET/POST/discover /api/v1/interfaces, GET/PUT /api/v1/settings, GET /api/v1/history, 全部 /api/v1/pcaps/*。

## 组件: 用户隔离 (跨用户 他人 token) - ISO-*

构造两个用户 A、B 各持有效 token；用 B 的 token 访问 A 的资源。用户级资源端点（strategy/task/pcap）的查询均 `WHERE id=? AND user_id=?`，B 看不到 A 的资源 -> 404。pcap handler 另有显式 `asset.UserID != userID` 二次校验。port-group 无 user_id（全局），单独标注。

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| ISO-STRAT-GET | B 取 A 的 strategy | TestIsolation_StrategyGet | B token GET /strategies/{A 的 id} | 404; "strategy not found" | SIMULATED | |
| ISO-STRAT-PUT | B 改 A 的 strategy | TestIsolation_StrategyUpdate | B token PUT /strategies/{A id} 合法 body | 404; "strategy not found" | SIMULATED | 注意: 校验顺序在归属检查前，非法 IP 会先 400（见 STRAT4-BR2） |
| ISO-STRAT-DEL | B 删 A 的 strategy | TestIsolation_StrategyDelete | B token DELETE /strategies/{A id} | 404; "strategy not found" | SIMULATED | |
| ISO-STRAT-LISTTASKS | B 查 A 的 strategy tasks | TestIsolation_StrategyListTasks | B token GET /strategies/{A id}/tasks | 404; "strategy not found" | SIMULATED | |
| ISO-STRAT-LIST | B 列策略只见自己的 | TestIsolation_StrategyList | A、B 各建策略；B GET /strategies | 200; data 数组含 B 的 id，不含 A 的 id | SIMULATED | |
| ISO-STRAT-CREATE | B 建同配置不与 A 去重 | TestIsolation_StrategyCreateDedup | A 建策略；B 用同 protocol+config+flow_control POST | 201（非 200 去重）；新 id；DB user_id=B | SIMULATED | config_hash 去重是 per-user |
| ISO-TASK-GET | B 取 A 的 task | TestIsolation_TaskGet | B token GET /tasks/{A id} | 404; "task not found" | SIMULATED | |
| ISO-TASK-START | B 启动 A 的 task | TestIsolation_TaskStart | B token POST /tasks/{A id}/start | 404; "task not found" | SIMULATED | |
| ISO-TASK-STOP | B 停 A 的 task | TestIsolation_TaskStop | B token POST /tasks/{A id}/stop | 404; "task not found" | SIMULATED | |
| ISO-TASK-DEL | B 删 A 的 task | TestIsolation_TaskDelete | B token DELETE /tasks/{A id} | 404; "task not found" | SIMULATED | |
| ISO-TASK-LIST | B 列任务只见自己的 | TestIsolation_TaskList | A、B 各建 task；B GET /tasks | 200; data.items 只含 B 的 task id | SIMULATED | |
| ISO-TASK-CREATE | B 用 A 的 strategy 建 task | TestIsolation_TaskCreateForeignStrategy | B token POST /tasks strategy_ids=[A 的 strategy id] | 400; "strategy <id> not found" | SIMULATED | strategy 校验 user-scoped |
| ISO-HISTORY | B 历史只见自己的 | TestIsolation_History | A、B 各有完成 task；B GET /history | 200; data.items 只含 B 的 | SIMULATED | |
| ISO-PCAP-GET | B 取 A 的 pcap | TestIsolation_PcapGet | B token GET /pcaps/{A asset id} | 404; "pcap asset" | SIMULATED | GetAsset(id,B) 找不到 + 二次 UserID 校验 |
| ISO-PCAP-DEL | B 删 A 的 pcap | TestIsolation_PcapDelete | B token DELETE /pcaps/{A id} | 404; "pcap asset" | SIMULATED | |
| ISO-PCAP-LIST | B 列 pcap 只见自己的 | TestIsolation_PcapList | A、B 各上传 pcap；B GET /pcaps | 200; data.items 只含 B 的 asset id | SIMULATED | |
| ISO-PCAP-FLOWS | B 取 A 的 flows | TestIsolation_PcapListFlows | B token GET /pcaps/{A id}/flows | 404; "pcap asset" | SIMULATED | |
| ISO-PCAP-GETFLOW | B 取 A 的 flow | TestIsolation_PcapGetFlow | B token GET /pcaps/{A id}/flows/{fid} | 404; "pcap asset" | SIMULATED | |
| ISO-PCAP-PKTS-FLOW | B 取 A 的 flow packets | TestIsolation_PcapListPackets | B token GET /pcaps/{A id}/flows/{fid}/packets | 404; "pcap asset" | SIMULATED | |
| ISO-PCAP-STREAM | B 取 A 的 stream | TestIsolation_PcapStream | B token GET /pcaps/{A id}/flows/{fid}/stream | 404; "pcap asset" | SIMULATED | |
| ISO-PCAP-BODY | B 取 A 的 body | TestIsolation_PcapBody | B token GET /pcaps/{A id}/flows/{fid}/body | 404; "pcap asset" | SIMULATED | |
| ISO-PCAP-PKTS-ASSET | B 取 A 的 by-asset packets | TestIsolation_PcapPacketsByAsset | B token GET /pcaps/{A id}/packets | 404; "pcap asset" | SIMULATED | |
| ISO-PCAP-GETPKT | B 取 A 的 packet | TestIsolation_PcapGetPacket | B token GET /pcaps/{A id}/packets/{pid} | 404; "pcap asset" | SIMULATED | |
| ISO-PCAP-PKTPAYLOAD | B 取 A 的 packet payload | TestIsolation_PcapPacketPayload | B token GET /pcaps/{A id}/packets/{pid}/payload | 404; "pcap asset" | SIMULATED | |
| ISO-PCAP-SEARCH | B 搜 A 的 pcap | TestIsolation_PcapSearch | B token POST /pcaps/{A id}/search | 404; "pcap asset" | SIMULATED | |
| ISO-PCAP-MATCH | B match-preview A 的 pcap | TestIsolation_PcapMatchPreview | B token POST /pcaps/{A id}/match-preview | 404; "pcap asset" | SIMULATED | |
| ISO-PCAP-EXTRACT | B extract A 的 pcap | TestIsolation_PcapExtract | B token POST /pcaps/{A id}/extract | 404; "pcap asset" | SIMULATED | |
| ISO-PCAP-DL | B 下载 A 的 pcap | TestIsolation_PcapDownload | B token GET /pcaps/{A id}/download | 404; "pcap asset" | SIMULATED | |
| ISO-PCAP-REPARSE | B reparse A 的 pcap | TestIsolation_PcapReparse | B token POST /pcaps/{A id}/reparse | 404; "pcap asset" | SIMULATED | |
| ISO-PCAP-IMPORT-DEDUP | B 上传同文件不与 A 去重 | TestIsolation_PcapImportDedup | A 上传 file.pcap；B 上传同一 file.pcap | 200；B 得到新 asset id（≠A 的）；A 的 asset 不变 | SIMULATED | GetAssetByHash(userID,...) per-user |
| ISO-PORTGROUP-DEL | port-group 无用户隔离 | TestIsolation_PortGroupGlobalDelete | A 建 port-group；B token DELETE /port-groups/{id} | 200; "port group deleted"（全局资源，任何用户可删） | SIMULATED | 记录 by-design 非隔离 |
| ISO-PORTGROUP-LIST | port-group 公开可见 | TestIsolation_PortGroupPublicList | A 建 group；无 token GET /port-groups | 200; data 含 A 的 group | SIMULATED | List/Get 公开 |

## 组件: AuthHandler (auth_handler.go)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| AUTH1-POS | A1.1 注册成功 | TestRegister_Success | {username:"alice",password:"password123",email:"a@b.com"} | status 201; body.code=0; message="created"; data.user_id/username/email 非空；DB 有该用户 role="user",enabled=true,PasswordHash≠明文 | SIMULATED | |
| AUTH1-NEG1 | A1.2 畸形 JSON | TestRegister_BadJSON | "not-json" | 400; "invalid request:" | SIMULATED | |
| AUTH1-NEG2 | A1.3 username 过短 | TestRegister_UsernameMin | username="ab" | 400; "invalid request:" 含 min | SIMULATED | |
| AUTH1-NEG3 | A1.3 username 过长 | TestRegister_UsernameMax | username=65 字符 | 400; "invalid request:" | SIMULATED | |
| AUTH1-NEG4 | A1.4 password 过短 | TestRegister_PasswordMin | password="short" | 400; 含 min=8 | SIMULATED | |
| AUTH1-NEG5 | A1.4 password 过长 | TestRegister_PasswordMax | password=129 字符 | 400 | SIMULATED | |
| AUTH1-NEG6 | A1.5 email 非法 | TestRegister_InvalidEmail | email="not-an-email" | 400; 含 email | SIMULATED | |
| AUTH1-NEG7 | A1.5 缺 email | TestRegister_MissingEmail | 无 email 字段 | 400（required） | SIMULATED | |
| AUTH1-NEG8 | A1.6 username 已存在 | TestRegister_UsernameExists | 先建 alice，再注册 alice | 400; "username already exists" | SIMULATED | |
| AUTH1-NEG9 | A1.7 email 已存在 | TestRegister_EmailExists | 先建 a@b.com，再用同 email 不同 username | 400; "email already exists" | SIMULATED | |
| AUTH1-NEG10 | A1.10 username+email 均冲突 | TestRegister_BothConflict | username+email 都已存在 | 400; "username already exists"（username 先检查） | SIMULATED | |
| AUTH1-NEG11 | A1.8 HashPassword 失败 | TestRegister_HashFail | 注入 hash 失败 | 500; "failed to hash password" | SIMULATED | 需 hash 注入缝（bcrypt 难触发）；目前不可注入，需重构 |
| AUTH1-NEG12 | A1.9 DB Create 失败 | TestRegister_DBCreateFail | 注入 DB Create 报错 | 500; "failed to create user:" | SIMULATED | 用坏 DB/包装器 |
| AUTH1-BR1 | A1.6 非 NotFound DB 错被吞 | TestRegister_UsernameCheckDBError | 使 username 查询返回非 NotFound 错 | 不返回 500；继续走到 create（潜在 bug：未区分非 NotFound） | SIMULATED | 记录现状: `err==nil` 判断把 DB 错当“不存在” |
| AUTH2-POS | A2.1 登录成功 | TestLogin_Success | 预建用户 | 200; code=0; message="success"; data.token 非空; expires_at≈now+24h; data.user_id/username 正确；DB 新 token 行 status="active" | SIMULATED | |
| AUTH2-POS2 | A2.10 last_login 更新 | TestLogin_LastLoginUpdated | 预建用户 last_login_at=nil | 登录后 DB last_login_at≈now | SIMULATED | |
| AUTH2-NEG1 | A2.2 畸形 JSON | TestLogin_BadJSON | "x" | 400 | SIMULATED | |
| AUTH2-NEG2 | A2.2 缺 username | TestLogin_MissingUsername | 无 username | 400 | SIMULATED | |
| AUTH2-NEG3 | A2.2 缺 password | TestLogin_MissingPassword | 无 password | 400 | SIMULATED | |
| AUTH2-NEG4 | A2.3 用户不存在 | TestLogin_UserNotFound | username="ghost" | 401; "invalid credentials"（防枚举） | SIMULATED | |
| AUTH2-NEG5 | A2.4 DB 查询错 | TestLogin_DBQueryError | 破坏 DB | 500; "failed to query user" | SIMULATED | |
| AUTH2-NEG6 | A2.5 用户禁用 | TestLogin_Disabled | Enabled=false | 401; "user is disabled" | SIMULATED | |
| AUTH2-NEG7 | A2.6 密码错 | TestLogin_WrongPassword | 错密码 | 401; "invalid credentials" | SIMULATED | |
| AUTH2-NEG8 | A2.7 GenerateToken 失败 | TestLogin_GenTokenFail | 注入 jwt 失败 | 500; "failed to generate token" | SIMULATED | 需可注入 jwtManager |
| AUTH2-BR1 | A2.8 token hash 冲突 | TestLogin_TokenHashCollision | 预置同 token_hash 行 | 200；旧 token 行被删；新 token 行建立 | SIMULATED | 极难自然触发；可预置同 hash 行 |
| AUTH2-NEG9 | A2.9 Create token 失败 | TestLogin_CreateTokenFail | DB Create 报错 | 500; "failed to store token" | SIMULATED | |
| AUTH2-BR2 | A2.10 last_login 更新失败被吞 | TestLogin_LastLoginUpdateFail | 使 Update 报错 | 仍 200；last_login_at 未变（未检错） | SIMULATED | 记录: 未检 Update 错误 |
| AUTH3-POS | A3.1 校验合法 token | TestValidateToken_Success | 合法 active 未过期 token | 200; data.valid=true; data.user_id/username/roles | SIMULATED | |
| AUTH3-NEG1 | A3.2 无 auth 头 | TestValidateToken_NoHeader | 不带 Authorization | 400; "missing authorization header" | SIMULATED | 注意是 400（非中间件 401） |
| AUTH3-NEG2 | A3.3 非 Bearer | TestValidateToken_NotBearer | "Basic x" | 400; "invalid authorization header format" | SIMULATED | |
| AUTH3-NEG3 | A3.3 Bearer 无 token | TestValidateToken_BearerNoToken | "Bearer" | 400; "invalid authorization header format" | SIMULATED | len<=7 |
| AUTH3-NEG4 | A3.4 JWT 无效 | TestValidateToken_InvalidJWT | "Bearer garbage" | 401; "invalid or expired token" | SIMULATED | |
| AUTH3-NEG5 | A3.5 token 不在 DB | TestValidateToken_NotInDB | 合法 JWT 但 DB 无 | 401; "token not found" | SIMULATED | |
| AUTH3-NEG6 | A3.6 DB 查询错 | TestValidateToken_DBError | 破坏 DB | 500; "failed to query token" | SIMULATED | |
| AUTH3-NEG7 | A3.7 token revoked | TestValidateToken_Revoked | status="revoked" | 401; "token is revoked" | SIMULATED | |
| AUTH3-NEG8 | A3.8 token 过期 | TestValidateToken_Expired | ExpiresAt=now-1h | 401; "token is expired" | SIMULATED | |
| AUTH4-POS | A4.3 注销成功 | TestLogout_Success | 合法 token | 200; "logged out"; data=null；DB token status="revoked" | SIMULATED | |
| AUTH4-BR1 | A4.1 无 auth 头 | TestLogout_NoHeader | 不带 Authorization | 200; "logged out"; data=null（no-op） | SIMULATED | |
| AUTH4-BR2 | A4.2 非 Bearer | TestLogout_NotBearer | "Basic x" | 200; "logged out"（tokenString="", no-op） | SIMULATED | |
| AUTH4-BR3 | A4.4 DB Update 失败被吞 | TestLogout_UpdateFail | 使 Update 报错 | 仍 200; "logged out"（未检错） | SIMULATED | |
| AUTH4-BR4 | A4.5 token 不在 DB | TestLogout_TokenNotInDB | 合法 JWT 但 DB 无 | 200; "logged out"（Update 0 行，no-op） | SIMULATED | |
| AUTH5-POS | A5.1 刷新成功 | TestRefresh_Success | 合法 token + context | 200; data.token 新非空; expires_at≈now+24h；DB 新 token active | SIMULATED | |
| AUTH5-NEG1 | A5.2 context 无 user | TestRefresh_NoUser | 直接调 handler 不注入 userID | 401; "invalid token" | SIMULATED | 中间件正常时不会到这 |
| AUTH5-NEG2 | A5.3 GenerateToken 失败 | TestRefresh_GenTokenFail | 注入 jwt 失败 | 500; "failed to generate token" | SIMULATED | |
| AUTH5-BR1 | A5.4 旧 token 被撤销 | TestRefresh_OldTokenRevoked | 合法 Bearer | 200；DB 旧 token_hash status="revoked"；新 token 建立 | SIMULATED | |
| AUTH5-BR2 | A5.5 非 Bearer 跳过撤销 | TestRefresh_NonBearerNoRevoke | "Basic x"（中间件已挡，直接调 handler） | 200；旧 token 未被 revoke；新 token 仍建立 | SIMULATED | 记录: 非 Bearer 跳过撤销逻辑 |
| AUTH5-NEG3 | A5.6 Create token 失败 | TestRefresh_CreateTokenFail | DB Create 报错 | 500; "failed to store token" | SIMULATED | |
| AUTH6-POS | A6.1 取 profile | TestGetProfile_Success | 预建用户 | 200; data.user_id/username/email/role/enabled/last_login_at/created_at 全部正确；role="user" | SIMULATED | |
| AUTH6-NEG1 | A6.2 无 user | TestGetProfile_NoUser | 直接调不注入 | 401; "user not authenticated" | SIMULATED | |
| AUTH6-NEG2 | A6.3 用户不在 DB | TestGetProfile_NotFound | context userID 指向已删用户 | 404; "user not found" | SIMULATED | |
| AUTH6-NEG3 | A6.4 DB 查询错 | TestGetProfile_DBError | 破坏 DB | 500; "failed to query user" | SIMULATED | |
| AUTH7-POS1 | A7.1 仅改 email | TestUpdateProfile_EmailOnly | email="new@b.com" | 200; "profile updated"; DB email=new@b.com；password_hash 未变 | SIMULATED | |
| AUTH7-POS2 | A7.2 仅改 password | TestUpdateProfile_PasswordOnly | password="newpass123" | 200; DB password_hash 变；auth.CheckPassword("newpass123",hash)=true | SIMULATED | |
| AUTH7-POS3 | A7.3 同改 | TestUpdateProfile_Both | email+password | 200；两者均变 | SIMULATED | |
| AUTH7-POS4 | A7.4 无改动 | TestUpdateProfile_NoChanges | email="",password="" | 200; "profile updated"；无 DB 写（len(updates)==0） | SIMULATED | |
| AUTH7-NEG1 | A7.5 无 user | TestUpdateProfile_NoUser | 不注入 | 401 | SIMULATED | |
| AUTH7-NEG2 | A7.6 不在 DB | TestUpdateProfile_NotFound | 已删用户 | 404; "user not found" | SIMULATED | |
| AUTH7-NEG3 | A7.7 DB 查询错 | TestUpdateProfile_DBError | 破坏 DB | 500; "failed to query user" | SIMULATED | |
| AUTH7-NEG4 | A7.8 admin 不可改 | TestUpdateProfile_Admin | role="admin" | 403; "admin account cannot be modified via API" | SIMULATED | |
| AUTH7-NEG5 | A7.9 畸形 JSON | TestUpdateProfile_BadJSON | "x" | 400 | SIMULATED | |
| AUTH7-NEG6 | A7.10 email 非法 | TestUpdateProfile_BadEmail | email="bad" | 400 | SIMULATED | |
| AUTH7-NEG7 | A7.11 password 过短 | TestUpdateProfile_PasswordMin | password="short" | 400 | SIMULATED | |
| AUTH7-NEG8 | A7.12 email 被占 | TestUpdateProfile_EmailTaken | 另一用户已用该 email | 400; "email already exists" | SIMULATED | |
| AUTH7-NEG9 | A7.13 HashPassword 失败 | TestUpdateProfile_HashFail | 注入失败 | 500; "failed to hash password" | SIMULATED | 需注入缝 |
| AUTH7-NEG10 | A7.14 DB Updates 失败 | TestUpdateProfile_UpdateFail | 使 Updates 报错 | 500; "failed to update profile" | SIMULATED | |
| AUTH7-BR1 | A7 email=当前 email 不报冲突 | TestUpdateProfile_SameEmail | email=自己当前 email | 200；不报 "email already exists"（req.Email!=user.Email 守卫） | SIMULATED | |
| AUTH8-POS | A8.1 注销账户 | TestDeleteProfile_Success | 普通用户 | 200; "account deleted"；DB 用户删除；所有该用户 token status="revoked" | SIMULATED | |
| AUTH8-NEG1 | A8.2 无 user | TestDeleteProfile_NoUser | 不注入 | 401 | SIMULATED | |
| AUTH8-NEG2 | A8.3 不在 DB | TestDeleteProfile_NotFound | 已删 | 404; "user not found" | SIMULATED | |
| AUTH8-NEG3 | A8.4 DB 查询错 | TestDeleteProfile_DBError | 破坏 DB | 500; "failed to query user" | SIMULATED | |
| AUTH8-NEG4 | A8.5 admin 不可删 | TestDeleteProfile_Admin | role="admin" | 403; "admin account cannot be deleted via API" | SIMULATED | |
| AUTH8-BR1 | A8.6 token 撤销失败被吞 | TestDeleteProfile_RevokeFail | 使 token Update 报错 | 仍 200; "account deleted"（用户已删，未检错） | SIMULATED | |
| AUTH8-NEG5 | A8.7 DB Delete 失败 | TestDeleteProfile_DeleteFail | 使 Delete 报错 | 500; "failed to delete account" | SIMULATED | |

## 组件: StrategyHandler (strategy_handler.go)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| STRAT1-POS | S1.1 创建成功 | TestStrategyCreate_Success | {name:"s1",protocol:"tcp",config:{src_ip:"10.0.0.1",dst_ip:"10.0.0.2"},flow_control:{type:"flows",value:10}} | 201; code=0; "created"; data.id 非空；DB user_id=caller, config_hash 非空, protocol="tcp" | SIMULATED | |
| STRAT1-NEG1 | S1.2 无 user | TestStrategyCreate_NoUser | 不注入 userID | 401; "user not authenticated" | SIMULATED | |
| STRAT1-NEG2 | S1.3 畸形 JSON | TestStrategyCreate_BadJSON | "x" | 400 | SIMULATED | |
| STRAT1-NEG3 | S1.4 缺 name | TestStrategyCreate_MissingName | 无 name | 400（required） | SIMULATED | |
| STRAT1-NEG4 | S1.5 缺 protocol | TestStrategyCreate_MissingProtocol | 无 protocol | 400 | SIMULATED | |
| STRAT1-NEG5 | S1.6 缺 config | TestStrategyCreate_MissingConfig | 无 config | 400 | SIMULATED | |
| STRAT1-NEG6 | S1.7 非法 src_ip | TestStrategyCreate_BadSrcIP | src_ip="bad" | 400; "invalid IP format: src_ip = bad" | SIMULATED | |
| STRAT1-NEG7 | S1.7 非法 dst_ip | TestStrategyCreate_BadDstIP | dst_ip="999.0.0.1" | 400; "invalid IP format: dst_ip = ..." | SIMULATED | |
| STRAT1-NEG8 | S1.8 非法 src_mac | TestStrategyCreate_BadSrcMAC | src_mac="zz" | 400; "invalid MAC format: src_mac = zz" | SIMULATED | |
| STRAT1-NEG9 | S1.8 非法 dst_mac | TestStrategyCreate_BadDstMAC | dst_mac="aa" | 400; "invalid MAC format: dst_mac = aa" | SIMULATED | |
| STRAT1-NEG10 | S1.9 dscp 越界 | TestStrategyCreate_DSCPOutOfRange | config.dscp=256 | 400（ValidateConfigRanges） | SIMULATED | 防止 uint8 截断到 0 |
| STRAT1-NEG11 | S1.9 vlan 越界 | TestStrategyCreate_VLANOutOfRange | config.vlan=4096 | 400 | SIMULATED | |
| STRAT1-NEG12 | S1.10 空 protocol | TestStrategyCreate_EmptyProtocol | protocol="" | 400; "invalid or missing protocol: " | SIMULATED | |
| STRAT1-NEG13 | S1.11 不支持 protocol | TestStrategyCreate_UnsupportedProtocol | protocol="sctp" | 400; "invalid or missing protocol: sctp" | SIMULATED | |
| STRAT1-NEG14 | S1.12 子配置非法 | TestStrategyCreate_BadSubConfig | protocol="icmp",config.icmp.type=999 | 400（ValidateProtocolSubConfigs） | SIMULATED | |
| STRAT1-BR1 | S1.13 FlowControl 默认 | TestStrategyCreate_DefaultFlowControl | 不传 flow_control | 201；DB FlowControl={"type":"flows","value":1} | SIMULATED | |
| STRAT1-NEG15 | S1.14 非法 flow_control type | TestStrategyCreate_BadFlowType | flow_control.type="xyz" | 400; "invalid flow_control type: must be flows, cps, bps, ratio, or time" | SIMULATED | |
| STRAT1-NEG16 | S1.15 flow_control value<=0 | TestStrategyCreate_NonPositiveValue | flow_control.value=0 | 400; "flow_control value must be positive" | SIMULATED | |
| STRAT1-NEG17 | S1.16 config Marshal 失败 | TestStrategyCreate_ConfigMarshalFail | config 含 chan/func 值 | 400; "invalid config format" | SIMULATED | |
| STRAT1-NEG18 | S1.17 flowControl Marshal 失败 | TestStrategyCreate_FCMarshalFail | 注入使 FC Marshal 失败 | 400; "invalid flow_control format" | SIMULATED | 需注入缝 |
| STRAT1-BR2 | S1.18 重复策略去重 | TestStrategyCreate_Dedup | 同 protocol+config+fc 再建 | 200（非 201）; code=0; message="success"; data.id=原 id; data.message="strategy already exists" | SIMULATED | 注意是 200 |
| STRAT1-NEG19 | S1.19 DB Create 失败 | TestStrategyCreate_DBCreateFail | DB Create 报错 | 500; "failed to create strategy:" | SIMULATED | |
| STRAT2-POS | S2.1 列出有策略 | TestStrategyList_HasItems | 预建策略 + 引用它的 task | 200; data 数组含策略; task_count=N（非零） | SIMULATED | |
| STRAT2-POS2 | S2.2 无策略 | TestStrategyList_Empty | 空用户 | 200; data=[] | SIMULATED | |
| STRAT2-NEG1 | S2.3 无 user | TestStrategyList_NoUser | 不注入 | 401 | SIMULATED | |
| STRAT2-NEG2 | S2.4 DB Find 失败 | TestStrategyList_DBFindFail | 破坏 DB | 500; "failed to list strategies:" | SIMULATED | |
| STRAT2-BR1 | S2.5 config 反序列化失败 | TestStrategyList_ConfigUnmarshalFail | 预置非法 config JSON | 200; config 字段为 nil（未检错） | SIMULATED | 记录: 静默降级 |
| STRAT2-BR2 | S2.6 flowControl 反序列化失败 | TestStrategyList_FCUnmarshalFail | 预置非法 FC JSON | 200; flowControl 为零值（未检错） | SIMULATED | |
| STRAT2-BR3 | S2.7 task count 查询失败 | TestStrategyList_TaskCountFail | 使 Count 报错 | 200; task_count=0（未检错） | SIMULATED | |
| STRAT2-BR4 | task_count 正确 | TestStrategyList_TaskCount | 策略被 2 个 task 引用 | 200; task_count=2 | SIMULATED | |
| STRAT3-POS | S3.1 取单个 | TestStrategyGet_Success | 自己的策略 | 200; data.id/name/protocol/config/flow_control 正确 | SIMULATED | |
| STRAT3-NEG1 | S3.2 无 user | TestStrategyGet_NoUser | 不注入 | 401 | SIMULATED | |
| STRAT3-NEG2 | S3.3 缺 :id | TestStrategyGet_MissingID | id="" | 400; "missing strategy id" | SIMULATED | |
| STRAT3-NEG3 | S3.4 不存在/非本人 | TestStrategyGet_NotFound | 他人/随机 id | 404; "strategy not found" | SIMULATED | |
| STRAT3-NEG4 | S3.5 DB 查询错 | TestStrategyGet_DBError | 破坏 DB | 500; "failed to get strategy:" | SIMULATED | |
| STRAT4-POS | S4.1 更新成功 | TestStrategyUpdate_Success | 改 name/protocol | 200; "strategy updated"; DB 字段变; config_hash 重算 | SIMULATED | |
| STRAT4-NEG1 | S4.2 无 user | TestStrategyUpdate_NoUser | 不注入 | 401 | SIMULATED | |
| STRAT4-NEG2 | S4.3 缺 :id | TestStrategyUpdate_MissingID | id="" | 400 | SIMULATED | |
| STRAT4-NEG3 | S4.4 畸形 JSON | TestStrategyUpdate_BadJSON | "x" | 400 | SIMULATED | |
| STRAT4-NEG4 | S4.5 非法 IP/MAC | TestStrategyUpdate_BadNetwork | src_ip="bad" | 400 | SIMULATED | |
| STRAT4-NEG5 | S4.6 越界 | TestStrategyUpdate_RangeFail | dscp=256 | 400 | SIMULATED | |
| STRAT4-NEG6 | S4.7 子配置非法 | TestStrategyUpdate_BadSubConfig | icmp.type=999 | 400 | SIMULATED | |
| STRAT4-NEG7 | S4.8 不存在/非本人 | TestStrategyUpdate_NotFound | 他人 id | 404; "strategy not found" | SIMULATED | |
| STRAT4-NEG8 | S4.9 DB 查询错 | TestStrategyUpdate_DBError | 破坏 DB | 500 | SIMULATED | |
| STRAT4-NEG9 | S4.10 非法 flow type | TestStrategyUpdate_BadFlowType | flow_control.type="x" | 400 | SIMULATED | |
| STRAT4-NEG10 | S4.11 flow value<=0 | TestStrategyUpdate_NonPositiveValue | value=0 | 400 | SIMULATED | |
| STRAT4-BR1 | S4.12 FlowControl nil | TestStrategyUpdate_FCNil | 不传 flow_control | 200；跳过 FC 校验；marshals nil | SIMULATED | |
| STRAT4-NEG11 | S4.13 config Marshal 失败 | TestStrategyUpdate_ConfigMarshalFail | config 含 chan | 400; "invalid config format" | SIMULATED | |
| STRAT4-NEG12 | S4.14 FC Marshal 失败 | TestStrategyUpdate_FCMarshalFail | 注入 | 400; "invalid flow_control format" | SIMULATED | |
| STRAT4-NEG13 | S4.15 DB Save 失败 | TestStrategyUpdate_DBSaveFail | 使 Save 报错 | 500; "failed to update strategy:" | SIMULATED | |
| STRAT4-BR2 | 校验顺序: 非法 config 先于归属 | TestStrategyUpdate_ValidationBeforeOwnership | 他人 strategy id + 非法 src_ip | 400（非 404）；记录信息泄漏倾向 | SIMULATED | validateConfigNetwork 在归属检查前 |
| STRAT5-POS | S5.1 删除成功 | TestStrategyDelete_Success | 无引用 | 200; "strategy deleted"; DB 删除 | SIMULATED | |
| STRAT5-NEG1 | S5.2 无 user | TestStrategyDelete_NoUser | 不注入 | 401 | SIMULATED | |
| STRAT5-NEG2 | S5.3 缺 :id | TestStrategyDelete_MissingID | id="" | 400 | SIMULATED | |
| STRAT5-NEG3 | S5.4 不存在/非本人 | TestStrategyDelete_NotFound | 他人 id | 404 | SIMULATED | |
| STRAT5-NEG4 | S5.5 DB 查询错 | TestStrategyDelete_DBError | 破坏 DB | 500 | SIMULATED | |
| STRAT5-NEG5 | S5.6 被任务引用 | TestStrategyDelete_UsedByTasks | 有 task 引用 | 400; "strategy is used by tasks, cannot delete" | SIMULATED | |
| STRAT5-NEG6 | S5.7 DB Delete 失败 | TestStrategyDelete_DBSaveFail | 使 Delete 报错 | 500 | SIMULATED | |
| STRAT5-BR1 | 仅被已完成任务引用也阻止 | TestStrategyDelete_UsedByCompletedTask | 引用 task 状态="completed" | 400（计数不分状态） | SIMULATED | 记录: 任何状态 task 均阻止 |
| STRAT6-POS | S6.1 列出引用任务 | TestStrategyListTasks_HasTasks | 预置引用 | 200; data 数组 TaskBrief{id,name,status} | SIMULATED | |
| STRAT6-POS2 | S6.2 无引用 | TestStrategyListTasks_Empty | 无 task | 200; data=[] | SIMULATED | |
| STRAT6-NEG1 | S6.3 无 user | TestStrategyListTasks_NoUser | 不注入 | 401 | SIMULATED | |
| STRAT6-NEG2 | S6.4 缺 :id | TestStrategyListTasks_MissingID | id="" | 400 | SIMULATED | |
| STRAT6-NEG3 | S6.5 不存在/非本人 | TestStrategyListTasks_NotFound | 他人 id | 404 | SIMULATED | |
| STRAT6-NEG4 | S6.6 DB 查询错 | TestStrategyListTasks_DBError | 破坏 DB | 500 | SIMULATED | |
| STRAT6-BR1 | S6.7 task Find 失败被吞 | TestStrategyListTasks_FindFail | 使 tasks Find 报错 | 200; data=[]（未检错） | SIMULATED | |

## 组件: TaskHandler (task_handler.go)

> 引擎依赖点（TASK2/TASK5/TASK6/TASK9）需 mock Engine 接口以断言 SubmitTask/StopTask/RegisterOutputWriter/RegisterDualWriter/UnregisterOutputWriter/FailTask/GetTaskStatus/RangeTaskStore 调用与错误注入。writer 创建（newInterfacePacketWriter/newPcapPacketWriter）为包级函数；接口模式用 pcap 输出（写 t.TempDir 文件）可全 SIMULATED；接口模式失败注入需可注入 writer 工厂（建议重构）。

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| TASK1-POS | T1.1 创建 task | TestTaskCreate_Success | name + 有效 strategy_id + pcap 输出 | 201; "created"; data.id 非空；DB status="pending", protocol=首策略 protocol | SIMULATED | |
| TASK1-NEG1 | T1.2 无 user | TestTaskCreate_NoUser | 不注入 | 401 | SIMULATED | |
| TASK1-NEG2 | T1.3 畸形 JSON | TestTaskCreate_BadJSON | "x" | 400 | SIMULATED | |
| TASK1-NEG3 | T1.4 缺 name | TestTaskCreate_MissingName | 无 name | 400 | SIMULATED | |
| TASK1-NEG4 | T1.5 空 strategy_ids | TestTaskCreate_EmptyStrategyIDs | strategy_ids=[] | 400; "at least one strategy_id is required" | SIMULATED | |
| TASK1-NEG5 | T1.6 port_group 缺 id | TestTaskCreate_PortGroupNoID | output_type="port_group",port_group_id="" | 400; "port_group_id is required for port_group output" | SIMULATED | |
| TASK1-NEG6 | T1.7 pcap 缺 path | TestTaskCreate_PcapNoPath | output_type="pcap",pcap_path="" | 400; "pcap_path is required for pcap output" | SIMULATED | |
| TASK1-NEG7 | T1.8 strategy 不存在/非本人 | TestTaskCreate_StrategyNotFound | 随机 strategy id | 400; "strategy <id> not found" | SIMULATED | |
| TASK1-NEG8 | T1.9 strategy 校验 DB 错 | TestTaskCreate_StrategyDBError | 破坏 DB | 500; "failed to validate strategy:" | SIMULATED | |
| TASK1-BR1 | T1.10 多策略主协议 | TestTaskCreate_MultiStrategyProtocol | [tcp_strategy, udp_strategy] | 201; DB protocol="tcp"（首个） | SIMULATED | |
| TASK1-BR2 | T1.11 幂等: 重复 active task | TestTaskCreate_Dedup | 已有 pending 同 sorted ids+output_config | 200（非 201）; "success"; data.id=原 id; data.message="task already exists" | SIMULATED | |
| TASK1-NEG9 | T1.12 DB Create 失败 | TestTaskCreate_DBCreateFail | 使 Create 报错 | 500; "failed to create task:" | SIMULATED | |
| TASK1-BR3 | T1.13 FlowControl nil | TestTaskCreate_FCNil | 不传 flow_control | 201; DB FlowControl 空 | SIMULATED | |
| TASK1-BR4 | 已完成 task 不算重复 | TestTaskCreate_CompletedNotDedup | 已有 completed 同配置 | 201（新建，不同 id） | SIMULATED | status IN pending/running |
| TASK1-BR5 | strategy_ids 顺序无关去重 | TestTaskCreate_DedupUnordered | [a,b] vs 已有 [b,a] | 200 去重（排序后比较） | SIMULATED | |
| TASK2-POS1 | T2.1 batch port_group | TestTaskBatch_PortGroup | batch+port_group 输出 + mock 引擎 | 201; data.id; DB status="running",protocol="batch"; mock SubmitTask 调一次, core.Task.OutputMode="interface",Interface=port group iface | SIMULATED | mock 引擎 |
| TASK2-POS2 | T2.2 batch pcap | TestTaskBatch_Pcap | batch+pcap 输出 t.TempDir | 201; mock SubmitTask OutputMode="pcap",PcapFile=resolved; pcap 文件创建 | SIMULATED | 真引擎或 mock |
| TASK2-NEG1 | T2.3 无 user | TestTaskBatch_NoUser | 不注入 | 401 | SIMULATED | |
| TASK2-NEG2 | T2.4 畸形 JSON | TestTaskBatch_BadJSON | "x" | 400 | SIMULATED | |
| TASK2-NEG3 | T2.5 batch 空 classes | TestTaskBatch_EmptyClasses | batch=nil 或 classes=[] | 400; "batch must contain at least one traffic class" | SIMULATED | |
| TASK2-NEG4 | T2.6 port_group 缺 id | TestTaskBatch_PortGroupNoID | port_group_id="" | 400 | SIMULATED | |
| TASK2-NEG5 | T2.7 pcap 缺 path | TestTaskBatch_PcapNoPath | pcap_path="" | 400 | SIMULATED | |
| TASK2-NEG6 | T2.8 port group 不在 DB | TestTaskBatch_PortGroupNotFound | 随机 port_group_id | 400; "port group not found: <id>" | SIMULATED | |
| TASK2-NEG7 | T2.9 port group 无接口 | TestTaskBatch_PortGroupNoInterface | PortsConfig[0].interface="" | 400; "port group has no interface configured" | SIMULATED | |
| TASK2-NEG8 | T2.10 pcap path 空 | TestTaskBatch_PcapResolveEmpty | output_type="pcap",pcap_path=""（绕过 T2.7 用非空白） | 400; "pcap_path is required" | SIMULATED | resolvePcapPath |
| TASK2-NEG9 | T2.11 Windows 风格路径 | TestTaskBatch_PcapWindows | pcap_path="C:\\x.pcap" | 400; 含 "Windows-style path" | SIMULATED | |
| TASK2-NEG10 | T2.12 UNC 路径 | TestTaskBatch_PcapUNC | pcap_path="\\\\srv\\share" | 400; 含 "UNC path" | SIMULATED | |
| TASK2-NEG11 | T2.13 建目录失败 | TestTaskBatch_MkdirFail | 只读父目录 | 400; "failed to create directory" | SIMULATED | |
| TASK2-BR1 | T2.14 dual-port via Interface2 | TestTaskBatch_DualPortInterface2 | output_config.interface2="eth1"+interface 模式 + mock 引擎 | 201; mock RegisterDualWriter(taskID,w1,w2) 调一次; RegisterOutputWriter 未调; coreTask.Interface2="eth1" | SIMULATED | 需可注入 writer 工厂或 mock |
| TASK2-BR2 | T2.15 dual-port via replay direction=dual | TestTaskBatch_DualPortReplayDirection | batch class replay.direction="dual" | 201; RegisterDualWriter 调用 | SIMULATED | |
| TASK2-NEG12 | T2.16 dual-port 接口缺 Interface2 | TestTaskBatch_DualPortMissingIface2 | direction=dual+interface 模式无 interface2 | 400; "dual-port replay requires a second interface (interface2 in output_config)" | SIMULATED | |
| TASK2-BR3 | T2.22 dual-port pcap | TestTaskBatch_DualPortPcap | interface2 设 + pcap 模式 | 201; RegisterDualWriter 调; 第二 writer 路径=pcapFile+".s2c"; 两文件创建 | SIMULATED | |
| TASK2-NEG13 | T2.17 接口 writer 创建失败 | TestTaskBatch_InterfaceWriterFail | 使 newInterfacePacketWriter 报错 | 500; "failed to create output writer:" | SIMULATED | 需注入工厂/无效 iface |
| TASK2-NEG14 | T2.18 pcap writer 创建失败 | TestTaskBatch_PcapWriterFail | 不可写 pcap 路径 | 500; "failed to create output writer:" | SIMULATED | |
| TASK2-NEG15 | T2.19 第二 writer 失败 | TestTaskBatch_SecondWriterFail | dual-port 第二 writer 失败 | 500; "failed to create second output writer:"; 第一 writer.Close() 调用 | SIMULATED | |
| TASK2-NEG16 | T2.20 DB 建 task 失败 | TestTaskBatch_DBCreateFail | 使 Create 报错 | 500; "failed to create task record:"; UnregisterOutputWriter 调用 | SIMULATED | |
| TASK2-NEG17 | T2.21 SubmitTask 失败 | TestTaskBatch_SubmitFail | mock SubmitTask 返错 | 400（err.Error()）; UnregisterOutputWriter 调; DB status="error",ErrorMessage 设 | SIMULATED | |
| TASK3-POS1 | T3.1 默认分页 | TestTaskList_Default | 无 query | 200; data.items/total/page=1/size=20 | SIMULATED | |
| TASK3-POS2 | T3.2 自定义分页 | TestTaskList_CustomPage | page=2,size=5 | 200; page=2,size=5; offset=5 | SIMULATED | |
| TASK3-BR1 | T3.3 非法 page | TestTaskList_InvalidPage | page=abc/0/-1 | 200; page=1 | SIMULATED | |
| TASK3-BR2 | T3.4 非法 size | TestTaskList_InvalidSize | size=abc/0/-1 | 200; size=20 | SIMULATED | |
| TASK3-BR3 | T3.5 size>100 | TestTaskList_SizeCapped | size=500 | 200; size=100 | SIMULATED | |
| TASK3-BR4 | T3.6 status 过滤 | TestTaskList_StatusFilter | status=running | 200; 仅 running | SIMULATED | |
| TASK3-BR5 | T3.7 非法 sort_by | TestTaskList_InvalidSortBy | sort_by="hacked; DROP TABLE" | 200; 按 created_at（无注入） | SIMULATED | |
| TASK3-BR6 | T3.8 升序 | TestTaskList_Ascending | sort_order=ascending | 200; 升序 | SIMULATED | |
| TASK3-BR7 | T3.9 降序默认 | TestTaskList_DescendingDefault | sort_order="" | 200; 降序 | SIMULATED | |
| TASK3-NEG1 | T3.10 无 user | TestTaskList_NoUser | 不注入 | 401 | SIMULATED | |
| TASK3-NEG2 | T3.11 DB Find 失败 | TestTaskList_DBFindFail | 破坏 DB | 500; "failed to list tasks:" | SIMULATED | |
| TASK3-POS3 | T3.12 空结果 | TestTaskList_Empty | 无 task | 200; items=[],total=0,page=1,size=20 | SIMULATED | |
| TASK4-POS | T4.1 取单 task 含策略 | TestTaskGet_Success | 自己 task | 200; data.strategies 填充（convertTaskToResponseWithDB） | SIMULATED | |
| TASK4-NEG1 | T4.2 无 user | TestTaskGet_NoUser | 不注入 | 401 | SIMULATED | |
| TASK4-NEG2 | T4.3 缺 :id | TestTaskGet_MissingID | id="" | 400; "missing task id" | SIMULATED | |
| TASK4-NEG3 | T4.4 不存在/非本人 | TestTaskGet_NotFound | 他人 id | 404; "task not found" | SIMULATED | |
| TASK4-NEG4 | T4.5 DB 查询错 | TestTaskGet_DBError | 破坏 DB | 500 | SIMULATED | |
| TASK4-BR1 | T4.6 策略查询部分失败被吞 | TestTaskGet_StrategyLookupFail | 使策略 Find 报错 | 200; strategies 可能空/部分（未检错） | SIMULATED | |
| TASK5-POS1 | T5.1 单策略 pcap 启动 | TestTaskStart_SinglePcap | pcap task + mock 引擎 | 200; "task started"; data.engine_task_ids=["{taskID}-{strategyID}"]; DB status="running",StartedAt 设; mock SubmitTask+RegisterOutputWriter 调 | SIMULATED | |
| TASK5-POS2 | T5.2 多策略 port_group | TestTaskStart_MultiPortGroup | 多策略 + port_group + mock | 200; 多 engine_task_ids; PortModel status="using",current_task_id 设 | SIMULATED | |
| TASK5-NEG1 | T5.3 无 user | TestTaskStart_NoUser | 不注入 | 401 | SIMULATED | |
| TASK5-NEG2 | T5.4 缺 :id | TestTaskStart_MissingID | id="" | 400 | SIMULATED | |
| TASK5-NEG3 | T5.5 不存在 | TestTaskStart_NotFound | 随机 id | 404 | SIMULATED | |
| TASK5-NEG4 | T5.6 DB 查询错 | TestTaskStart_DBError | 破坏 DB | 500 | SIMULATED | |
| TASK5-NEG5 | T5.7 已 running/starting | TestTaskStart_AlreadyRunning | status="running" | 400; "task is already running" | SIMULATED | |
| TASK5-NEG6 | T5.8 乐观锁失败 | TestTaskStart_OptimisticLock | 读后并发改 status 使 RowsAffected=0 | 400; "task status changed, please retry" | SIMULATED | 预改 status |
| TASK5-NEG7 | T5.9 strategy_ids 损坏 | TestTaskStart_CorruptStrategyIDs | DB strategy_ids="{bad" | 500; "corrupt strategy_ids in task record"; DB status="error" | SIMULATED | |
| TASK5-NEG8 | T5.10 strategy 已删 | TestTaskStart_StrategyNotFound | strategy 被删 | 400; "strategy <id> not found"; DB status="error" | SIMULATED | |
| TASK5-NEG9 | T5.12 全策略转换失败 | TestTaskStart_AllStrategiesFail | 使所有 StrategyModelToTask 报错 | 400; "no valid strategies to execute"; DB status="error" | SIMULATED | |
| TASK5-BR1 | T5.11/T5.18 部分失败 | TestTaskStart_PartialFail | 1/2 策略转换失败 | 200（≥1 成功）; 失败者不在 engine_task_ids | SIMULATED | |
| TASK5-NEG10 | T5.13 pcap 解析失败 | TestTaskStart_PcapResolveFail | pcap_path 非法 | 400（resolvePcapPath err）; DB status="error" | SIMULATED | |
| TASK5-BR2 | T5.14 pcap path 解析并回写 | TestTaskStart_PcapResolveUpdate | 相对路径 pcap | 200; DB task.OutputConfig 含 resolved path; coreTasks PcapFile=resolved | SIMULATED | |
| TASK5-NEG11 | T5.15 接口 writer 全失败 | TestTaskStart_InterfaceWriterAllFail | 使所有 newInterfacePacketWriter 报错 | 400; "failed to create output writers:"; DB status="error" | SIMULATED | |
| TASK5-NEG12 | T5.16 pcap writer 全失败 | TestTaskStart_PcapWriterAllFail | 使所有 newPcapPacketWriter 报错 | 400 | SIMULATED | |
| TASK5-NEG13 | T5.17 全 writer 失败 | TestTaskStart_AllWritersFail | 全失败 | 400; "failed to create output writers:"; DB status="error" | SIMULATED | |
| TASK5-BR3 | T5.18 部分 writer 失败 | TestTaskStart_PartialWriterFail | 1/2 writer 失败 | 200; 失败策略跳过; 余者提交 | SIMULATED | |
| TASK5-BR4 | T5.19/T5.20 SubmitTask 部分失败 | TestTaskStart_PartialSubmitFail | mock 1 个 SubmitTask 报错 | 200（≥1 成功）; 失败 ct UnregisterOutputWriter | SIMULATED | |
| TASK5-NEG14 | T5.21 全 SubmitTask 失败 | TestTaskStart_AllSubmitFail | mock 全报错 | 500; "failed to start any strategy"; DB status="error" | SIMULATED | |
| TASK5-BR5 | T5.22 port_group 端口预留 | TestTaskStart_PortReservation | port_group task | 200; PortModel status="using",current_task_id=task id | SIMULATED | |
| TASK5-BR6 | T5.23 端口已被占 | TestTaskStart_PortAlreadyUsed | PortModel status!="idle" 或 current_task_id!="" | 200; 该端口未被预留（状态不变） | SIMULATED | |
| TASK5-BR7 | T5.24 output_config 解析失败 | TestTaskStart_PortGroupConfigParseFail | DB OutputConfig 损坏 | 200; 预留静默跳过（未检错） | SIMULATED | |
| TASK6-POS1 | T6.1 停止单策略 | TestTaskStop_Single | running task + mock | 200; "task stopped"; data.stopped_engine_tasks=["{id}-{sid}"]; DB status="stopped",CompletedAt 设; mock StopTask+UnregisterOutputWriter 调; 端口释放 | SIMULATED | |
| TASK6-POS2 | T6.2 停止多策略 | TestTaskStop_Multi | 多策略 | 200; 多 stopped ids | SIMULATED | |
| TASK6-NEG1 | T6.3 无 user | TestTaskStop_NoUser | 不注入 | 401 | SIMULATED | |
| TASK6-NEG2 | T6.4 缺 :id | TestTaskStop_MissingID | id="" | 400 | SIMULATED | |
| TASK6-NEG3 | T6.5 不存在 | TestTaskStop_NotFound | 随机 id | 404 | SIMULATED | |
| TASK6-NEG4 | T6.6 DB 查询错 | TestTaskStop_DBError | 破坏 DB | 500 | SIMULATED | |
| TASK6-NEG5 | T6.7 非 running | TestTaskStop_NotRunning | status="pending" | 400; "task is not running" | SIMULATED | |
| TASK6-BR1 | T6.8 strategy_ids 损坏 | TestTaskStop_CorruptStrategyIDs | DB strategy_ids="{bad" | 200; "task stopped (engine cleanup may be incomplete)"; DB status="stopped" | SIMULATED | |
| TASK6-BR2 | T6.9 一个 StopTask 失败 | TestTaskStop_PartialFail | mock 1 个 StopTask 报错 | 200; 失败 id 不在 stopped 列表; 余者在 | SIMULATED | |
| TASK6-BR3 | T6.10 端口释放 | TestTaskStop_PortRelease | port_group task | 200; PortModel status="idle",current_task_id="" | SIMULATED | |
| TASK6-BR4 | T6.11 非 port_group 不释放 | TestTaskStop_NoPortGroup | output_type="pcap" | 200; releasePortGroupPorts 早返回（无端口操作） | SIMULATED | |
| TASK6-BR5 | T6.12 port group 不在 DB | TestTaskStop_PortGroupNotFound | port_group_id 随机 | 200; release 早返回（无操作） | SIMULATED | |
| TASK6-BR6 | T6.13 仅释放本 task 端口 | TestTaskStop_OnlyOwnPorts | 两 task 共用端口组 | 200; 仅 current_task_id=本 task 的端口释放; 他 task 端口不变 | SIMULATED | |
| TASK7-POS | T7.1 删除已完成 task | TestTaskDelete_Success | status="completed" | 200; "task deleted"; DB 删除 | SIMULATED | |
| TASK7-NEG1 | T7.2 无 user | TestTaskDelete_NoUser | 不注入 | 401 | SIMULATED | |
| TASK7-NEG2 | T7.3 缺 :id | TestTaskDelete_MissingID | id="" | 400 | SIMULATED | |
| TASK7-NEG3 | T7.4 不存在 | TestTaskDelete_NotFound | 随机 id | 404 | SIMULATED | |
| TASK7-NEG4 | T7.5 DB 查询错 | TestTaskDelete_DBError | 破坏 DB | 500 | SIMULATED | |
| TASK7-NEG5 | T7.6 running 不可删 | TestTaskDelete_Running | status="running" | 400; "cannot delete running task, stop it first" | SIMULATED | |
| TASK7-NEG6 | T7.7 DB Delete 失败 | TestTaskDelete_DBDeleteFail | 使 Delete 报错 | 500 | SIMULATED | |
| TASK8-POS1 | T8.1 默认历史 | TestHistory_Default | 无 query | 200; 仅 completed/failed/stopped/error | SIMULATED | |
| TASK8-POS2 | T8.2 自定义分页 | TestHistory_CustomPage | page=2,size=5 | 200 | SIMULATED | |
| TASK8-BR1 | T8.3 start_time 合法 | TestHistory_StartTimeValid | start_time=unix | 200; created_at>=start_time 过滤 | SIMULATED | |
| TASK8-BR2 | T8.4 start_time 非法 | TestHistory_StartTimeInvalid | start_time=abc | 200; 忽略（不报错） | SIMULATED | |
| TASK8-BR3 | T8.5 end_time 合法 | TestHistory_EndTimeValid | end_time=unix | 200; created_at<=end_time | SIMULATED | |
| TASK8-BR4 | T8.6 end_time 非法 | TestHistory_EndTimeInvalid | end_time=abc | 200; 忽略 | SIMULATED | |
| TASK8-BR5 | T8.7 status 过滤 | TestHistory_StatusFilter | status=failed | 200; 仅 failed | SIMULATED | |
| TASK8-BR6 | T8.8 非法 sort_by | TestHistory_InvalidSortBy | sort_by="x" | 200; created_at | SIMULATED | |
| TASK8-BR7 | T8.9 升序 | TestHistory_Ascending | sort_order=ascending | 200; 升序 | SIMULATED | |
| TASK8-NEG1 | T8.10 无 user | TestHistory_NoUser | 不注入 | 401 | SIMULATED | |
| TASK8-NEG2 | T8.11 DB Find 失败 | TestHistory_DBFindFail | 破坏 DB | 500; "failed to list history:" | SIMULATED | |
| TASK8-POS3 | T8.12 无历史 | TestHistory_Empty | 无 task | 200; items=[],total=0 | SIMULATED | |
| TASK8-BR8 | pending/running 被排除 | TestHistory_ExcludesActive | 有 pending+completed | 200; items 不含 pending | SIMULATED | |
| TASK9-BR1 | T9.1 task 不在 DB | TestOnEngineTaskComplete_NotInDB | 调 onEngineTaskComplete 随机 id | 无 panic; DB 无写; 无 ws 广播 | SIMULATED | 直接调回调 |
| TASK9-BR2 | T9.2 子任务仍跑 | TestOnEngineTaskComplete_SubTasksRunning | mock GetTaskStatus 返回存在 | allDone=false; DB status 不变 | SIMULATED | |
| TASK9-POS1 | T9.3 全完成无失败 | TestOnEngineTaskComplete_Completed | mock 全不存在 + 无 failedTasks | DB status="completed",Progress=100,CompletedAt 设 | SIMULATED | |
| TASK9-POS2 | T9.4 全完成有失败 | TestOnEngineTaskComplete_Failed | failedTasks 有项 | DB status="failed",ErrorMessage 含 "output error" | SIMULATED | |
| TASK9-BR3 | T9.5 wsHub nil | TestOnEngineTaskComplete_NoWS | wsHub=nil | 无 panic; DB 仍更新 | SIMULATED | |
| TASK9-BR4 | T9.6 status 非 running | TestOnEngineTaskComplete_NotRunningGuard | DB task.Status="stopped" | 无 status 更新（竞态守卫） | SIMULATED | |
| TASK9-BR5 | T9.7 复合 ID 取 parent | TestOnEngineProgress_CompositeID | engineTaskID="{taskID}-{sid}" | parentTaskID=parts[0]; DB parent progress 更新 | SIMULATED | |
| TASK9-BR6 | T9.8 单段 ID | TestOnEngineProgress_SinglePartID | engineTaskID 无 "-" | parentTaskID=engineTaskID | SIMULATED | |
| TASK9-BR7 | T9.9 节流 <2s | TestOnEngineProgress_Throttled | 2s 内连续调 | 第二次早返回; DB 不更新 | SIMULATED | |
| TASK9-BR8 | T9.10 无兄弟子任务 | TestOnEngineProgress_NoSiblings | mock RangeTaskStore 无兄弟 | avgProgress=progress（1 子任务） | SIMULATED | |
| TASK9-BR9 | T9.11 ws 广播 | TestOnEngineProgress_WS | wsHub 非 nil（fake） | BroadcastToTask 调 TypeProgressUpdate | SIMULATED | fake hub 记录调用 |
| TASK9-BR10 | T9.12 短 engineTaskID | TestOnEngineOutputError_ShortID | len<=37 | taskID=engineTaskID; failedTasks[engineTaskID] 设; mock FailTask+UnregisterOutputWriter 调 | SIMULATED | |
| TASK9-BR11 | T9.13 长 engineTaskID | TestOnEngineOutputError_LongID | len>37 | taskID=engineTaskID[:36]（UUID 提取） | SIMULATED | |
| TASK9-BR12 | 进度聚合多子任务 | TestOnEngineProgress_Aggregate | 2 子任务 progress=40,60 | DB progress=50（平均） | SIMULATED | |
| TASK9-BR13 | 完成时释放端口+注销 writer | TestOnEngineTaskComplete_Cleanup | port_group task 完成 | releasePortGroupPorts 调; 每策略 UnregisterOutputWriter + 纯 taskID UnregisterOutputWriter 调 | SIMULATED | |

## 组件: PortGroupHandler (port_group_handler.go)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| PORT1-POS | P1.1 创建成功 | TestPortGroupCreate_Success | ports:[{interface:"eth0",weight:1}] | 201; code=0; "created"; data.id 非空; data.name="port_group_<8hex>"; DB PortsConfig 按接口名排序 | SIMULATED | |
| PORT1-NEG1 | P1.2 畸形 JSON | TestPortGroupCreate_BadJSON | "x" | 400 | SIMULATED | |
| PORT1-NEG2 | P1.3 空 ports | TestPortGroupCreate_EmptyPorts | ports=[] | 400（min=1） | SIMULATED | |
| PORT1-NEG3 | P1.4 接口名空 | TestPortGroupCreate_EmptyInterface | 直接构造 PortConfig{Interface:""} 绕过 binding | 400; "interface name is required" | SIMULATED | binding required 已挡 JSON 路径; 此点测显式循环 |
| PORT1-NEG4 | P1.5 ports Marshal 失败 | TestPortGroupCreate_MarshalFail | 注入使 Marshal 失败 | 400; "invalid ports config format" | SIMULATED | []PortConfig 正常不可失败; 需注入缝 |
| PORT1-BR1 | P1.6 重复去重 | TestPortGroupCreate_Dedup | 同 ports 再建 | 200（非 201）; "success"; data.id=原; data.message="port group already exists" | SIMULATED | |
| PORT1-NEG5 | P1.7 DB Create 失败 | TestPortGroupCreate_DBCreateFail | 使 Create 报错 | 500; "failed to create port group:" | SIMULATED | |
| PORT1-BR2 | ports 顺序无关去重 | TestPortGroupCreate_OrderInvariant | [{eth1},{eth0}] vs [{eth0},{eth1}] | 同 name/id（排序后 hash） | SIMULATED | |
| PORT2-POS1 | P2.1 有 group | TestPortGroupList_HasItems | 预建 | 200; data 数组 PortGroupResponse | SIMULATED | |
| PORT2-POS2 | P2.2 无 group | TestPortGroupList_Empty | 空 | 200; data=[] | SIMULATED | |
| PORT2-NEG1 | P2.3 DB Find 失败 | TestPortGroupList_DBFindFail | 破坏 DB | 500; "failed to list port groups:" | SIMULATED | |
| PORT2-BR1 | P2.4 PortsConfig 反序列化失败 | TestPortGroupList_UnmarshalFail | 预置非法 JSON | 200; ports_config=nil（未检错） | SIMULATED | |
| PORT2-BR2 | 公开无需鉴权 | TestPortGroupList_Public | 无 token | 200（非 401） | SIMULATED | |
| PORT3-POS | P3.1 取单个 | TestPortGroupGet_Success | 预建 | 200; PortGroupResponse | SIMULATED | |
| PORT3-NEG1 | P3.2 缺 :id | TestPortGroupGet_MissingID | id="" | 400; "missing port group id" | SIMULATED | |
| PORT3-NEG2 | P3.3 不存在 | TestPortGroupGet_NotFound | 随机 id | 404; "port group not found" | SIMULATED | |
| PORT3-NEG3 | P3.4 DB 查询错 | TestPortGroupGet_DBError | 破坏 DB | 500 | SIMULATED | |
| PORT3-BR1 | 公开无需鉴权 | TestPortGroupGet_Public | 无 token | 200 | SIMULATED | |
| PORT4-POS | P4.1 删除成功 | TestPortGroupDelete_Success | 无引用 | 200; "port group deleted"; DB 删除 | SIMULATED | |
| PORT4-NEG1 | P4.2 缺 :id | TestPortGroupDelete_MissingID | id="" | 400 | SIMULATED | |
| PORT4-NEG2 | P4.3 不存在 | TestPortGroupDelete_NotFound | 随机 id | 404 | SIMULATED | |
| PORT4-NEG3 | P4.4 DB 查询错 | TestPortGroupDelete_DBError | 破坏 DB | 500 | SIMULATED | |
| PORT4-NEG4 | P4.5 被任务引用 | TestPortGroupDelete_UsedByTasks | task output_config 含 id | 400; "port group is used by tasks, cannot delete" | SIMULATED | LIKE 搜索 |
| PORT4-NEG5 | P4.6 DB Delete 失败 | TestPortGroupDelete_DBDeleteFail | 使 Delete 报错 | 500 | SIMULATED | |
| PORT4-BR1 | 无用户隔离 | TestPortGroupDelete_AnyUser | A 建 group,B 删 | 200; "port group deleted"（全局资源） | SIMULATED | by-design |
| PORT4-BR2 | LIKE 误命中 | TestPortGroupDelete_LikeFalsePositive | output_config 含 id 子串但非 port_group 引用 | 400（LIKE 误判） | SIMULATED | 记录: 子串匹配可能误拦 |

## 组件: SystemHandler (system.go)

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| SYS1-POS | Y1.1 引擎运行+DB 正常 | TestSystemStatus_Healthy | mock 引擎 IsRunning=true, CountActiveTasks=3 | 200; running=true; active_tasks=3; buffer_status/cpu_usage/memory_mb/uptime/num_gc/gc_pause_ms 均非零（除可能 0 的 cpu） | SIMULATED | |
| SYS1-BR1 | Y1.2 db nil | TestSystemStatus_NilDB | h.db=nil | 200; active_tasks=0 | SIMULATED | |
| SYS1-BR2 | Y1.3 CountActiveTasks 错 | TestSystemStatus_CountError | mock CountActiveTasks 报错 | 200; active_tasks=0（未检错） | SIMULATED | |
| SYS1-BR3 | Y1.4 引擎未运行 | TestSystemStatus_EngineStopped | IsRunning=false | 200; running=false | SIMULATED | |
| SYS2-POS | Y2.1 协议列表 | TestSystemProtocols_List | — | 200; data=["tcp","udp","http","dns","icmp","arp"]（精确顺序） | SIMULATED | |
| SYS3-POS | Y3.1 聚合统计 | TestSystemStats_Aggregate | mock GetStats 返回多任务 | 200; packets_sent/bytes_sent/current_pps/current_bps 求和正确; protocols 聚合 | SIMULATED | |
| SYS3-BR1 | Y3.2 无 tasks 键 | TestSystemStats_NoTasksKey | mock GetStats 无 "tasks" | 200; 总计全 0 | SIMULATED | |
| SYS3-BR2 | Y3.3 单任务缺 stats | TestSystemStats_TaskMissingStats | task 无 "stats" | 200; 该任务跳过 | SIMULATED | |
| SYS3-BR3 | Y3.4 packets_sent 非 int64 | TestSystemStats_PacketsTypeMismatch | stats.packets_sent="x" | 200; 该项跳过 | SIMULATED | |
| SYS3-BR4 | Y3.5 current_pps 非 float64 | TestSystemStats_PPSMismatch | stats.current_pps="x" | 200; 该项跳过 | SIMULATED | |
| SYS3-BR5 | Y3.6 protocol 缺/类型错 | TestSystemStats_ProtocolMismatch | task.protocol=123 | 200; 不计入 | SIMULATED | |
| SYS3-BR6 | Y3.7 db nil | TestSystemStats_NilDB | h.db=nil | 200; 仅引擎协议 | SIMULATED | |
| SYS3-BR7 | Y3.8 DB 协议分布 | TestSystemStats_DBProtocols | mock CountTasksByProtocol 返回 {tcp:5} | 200; protocols 合并 tcp=5+引擎 | SIMULATED | |
| SYS3-BR8 | Y3.9 DB 协议查询失败 | TestSystemStats_DBProtocolsFail | mock CountTasksByProtocol 报错 | 200; DB 计数跳过（未检错） | SIMULATED | |
| SYS4-POS | H1.1 健康检查 | TestHealthCheck | — | 200; body={"status":"healthy"}（精确）; 无需 token | SIMULATED | |
| SYS5-POS | H2.1 就绪 | TestReadyCheck_Ready | IsRunning=true | 200; {"status":"ready","database":"connected","redis":"connected"} | SIMULATED | redis 为硬编码 TODO |
| SYS5-NEG1 | H2.2 未就绪 | TestReadyCheck_NotReady | IsRunning=false | 503; {"status":"not ready","reason":"engine not running"} | SIMULATED | |
| SYS5-BR1 | 公开无需鉴权 | TestReadyCheck_Public | 无 token | 200/503（非 401） | SIMULATED | |

## 组件: PcapHandler (pcap_handler.go) — 由源码派生（枚举未细化）

> 基础设施同 pcap_handler_test.go: 内存 SQLite + dataDir=t.TempDir + 上传构造的小 pcap。requireReady/cancel-import/dual-port 见标注。cross-user 见 ISO-PCAP-*。

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| PCAP-IMPORT-POS | Import 成功 | TestPcapImport_Success | 上传合法 pcap（含 1 TCP 流） | 200; data.Status="ready"; FlowCount=1; PacketCount>0; ByteCount>0; FileHash 非空; StoragePath/PayloadsPath 文件存在 | SIMULATED | 复用 writePcapForREST |
| PCAP-IMPORT-NEG1 | Import 缺 file | TestPcapImport_NoFile | 无 multipart file | 400; "file is required (multipart field 'file')" | SIMULATED | |
| PCAP-IMPORT-NEG2 | Import 文件过大 | TestPcapImport_TooLarge | 构造 file.Size>2GB（或注入） | 400; "file too large" | SIMULATED | 难造 2GB; 可注入 size 或跳过 |
| PCAP-IMPORT-BR1 | Import 去重 | TestPcapImport_Dedup | 同文件二次上传同用户 | 200; 返回原 asset id; 无新记录; 临时文件删 | SIMULATED | |
| PCAP-IMPORT-BR2 | Import 并发去重 | TestPcapImport_ConcurrentDedup | GetAssetByHash miss 后 CreateAsset 唯一索引失败 | 200; 返回既有 asset（re-fetch winner） | SIMULATED | 需注入 CreateAsset 失败 |
| PCAP-IMPORT-NEG3 | Import 解析失败 | TestPcapImport_ParseFail | 上传非 pcap 内容 | 400; "parse failed:"; asset.Status="error" | SIMULATED | |
| PCAP-IMPORT-NEG4 | Import CreateFlows 失败 | TestPcapImport_CreateFlowsFail | 注入 repo.CreateFlows 报错 | 500; asset.Status="error" "store flows:" | SIMULATED | 需可注入 repo |
| PCAP-IMPORT-NEG5 | Import CreatePackets 失败 | TestPcapImport_CreatePacketsFail | 注入 CreatePackets 报错 | 500; asset.Status="error" | SIMULATED | |
| PCAP-IMPORT-NEG6 | Import finalize 失败 | TestPcapImport_FinalizeFail | 注入 UpdateAsset 报错 | 500; "finalize asset:" | SIMULATED | |
| PCAP-IMPORT-NEG7 | Import file.Open 失败 | TestPcapImport_OpenFail | 注入 file.Open 报错 | 500; "open upload:" | SIMULATED | 需注入缝 |
| PCAP-IMPORT-NEG8 | Import io.Copy 失败 | TestPcapImport_CopyFail | 注入 Copy 报错 | 500; "save upload:"; 临时文件删 | SIMULATED | |
| PCAP-IMPORT-NEG9 | Import Rename 失败 | TestPcapImport_RenameFail | 使 Rename 报错 | 500; "finalize pcap file:"; tmp 删 | SIMULATED | |
| PCAP-IMPORT-NEG10 | Import MkdirAll 失败 | TestPcapImport_MkdirFail | 只读 dataDir | 500; "mkdir data dir:" | SIMULATED | |
| PCAP-IMPORT-BR3 | Import 跨用户不去重 | (见 ISO-PCAP-IMPORT-DEDUP) | — | — | SIMULATED | 在 ISO 节 |
| PCAP-IMPORT-BR4 | LinkType=DLT_EN10MB | TestPcapImport_LinkType | 合法以太 pcap | 200; data.LinkType=1 | SIMULATED | |
| PCAP-IMPORT-BR5 | ParserVersion 记录 | TestPcapImport_ParserVersion | 合法 pcap | 200; data.ParserVersion=pcapparser.ParserVersion | SIMULATED | |
| PCAP-LIST-POS | List 分页 | TestPcapList_Success | 预建多 asset | 200; {items,total,page,size} | SIMULATED | |
| PCAP-LIST-BR1 | List 分页边界 | TestPcapList_PaginationBounds | page=0,size=0/201 | 200; page=1,size=20 | SIMULATED | |
| PCAP-LIST-BR2 | List status 过滤 | TestPcapList_StatusFilter | status=ready | 200; 仅 ready | SIMULATED | |
| PCAP-LIST-NEG1 | List repo 错 | TestPcapList_RepoError | 注入 ListAssets 报错 | 500; "list assets:" | SIMULATED | |
| PCAP-GET-POS | Get 单 asset | TestPcapGet_Success | 自己 asset | 200; data asset 详情 | SIMULATED | |
| PCAP-GET-NEG1 | Get 不存在 | TestPcapGet_NotFound | 随机 id | 404; "pcap asset" | SIMULATED | |
| PCAP-GET-BR1 | Get 缺 :id | TestPcapGet_MissingID | id="" | 404（GetAsset("",uid) NotFound） | SIMULATED | |
| PCAP-DEL-POS | Delete 成功 | TestPcapDelete_Success | ready 无引用 | 200; "asset deleted"; DB asset+flows+packets 删; .pcap/.payloads 文件删 | SIMULATED | |
| PCAP-DEL-NEG1 | Delete reindexing | TestPcapDelete_Reindexing | Status="reindexing" | 400; "asset is reindexing; wait for completion" | SIMULATED | |
| PCAP-DEL-BR1 | Delete cancel-import 语义 | TestPcapDelete_CancelImport | Status="importing" | 200; "import cancelled, asset and partial files removed" | SIMULATED | cancel-import |
| PCAP-DEL-NEG2 | Delete 被引用无 force | TestPcapDelete_ReferencedNoForce | CountReplayReferences>0 | 400; "asset referenced by N replay strateg(ies)/task(s); use ?force=true to invalidate" | SIMULATED | |
| PCAP-DEL-BR2 | Delete 被引用+force | TestPcapDelete_ReferencedForce | 同上 + ?force=true | 200; "asset deleted"（使引用失效） | SIMULATED | |
| PCAP-DEL-NEG3 | Delete DeleteAssetComplete 错 | TestPcapDelete_RepoError | 注入报错 | 500; "delete asset:" | SIMULATED | |
| PCAP-DEL-BR3 | Delete 前关缓存文件 | TestPcapDelete_CloseCachedFile | 已被读取过的 asset | 200; CloseCachedFile 调用（无句柄泄漏） | SIMULATED | |
| PCAP-DEL-BR4 | Delete 缺 :id | TestPcapDelete_MissingID | id="" | 404 | SIMULATED | |
| PCAP-FLOWS-POS | ListFlows | TestPcapListFlows_Success | ready asset | 200; {items,total,page,size} | SIMULATED | |
| PCAP-FLOWS-NEG1 | requireReady importing | TestPcapListFlows_NotReadyImporting | Status="importing" | 400; "asset is not ready (status: importing)..." | SIMULATED | requireReady |
| PCAP-FLOWS-NEG2 | requireReady error | TestPcapListFlows_NotReadyError | Status="error" | 400; "asset is not ready (status: error)..." | SIMULATED | |
| PCAP-FLOWS-NEG3 | requireReady reindexing | TestPcapListFlows_NotReadyReindexing | Status="reindexing" | 400 | SIMULATED | |
| PCAP-FLOWS-BR1 | ListFlows 分页边界 | TestPcapListFlows_Pagination | page=0,size=0/501 | 200; page=1,size=50 | SIMULATED | |
| PCAP-FLOWS-NEG4 | ListFlows repo 错 | TestPcapListFlows_RepoError | 注入 ListFlowsByAsset 报错 | 500; "list flows:" | SIMULATED | |
| PCAP-GETFLOW-POS | GetFlow | TestPcapGetFlow_Success | flow 属于 asset | 200; data flow 详情 | SIMULATED | |
| PCAP-GETFLOW-NEG1 | GetFlow 不存在 | TestPcapGetFlow_NotFound | 随机 fid | 404; "flow" | SIMULATED | |
| PCAP-GETFLOW-NEG2 | GetFlow 属他 asset | TestPcapGetFlow_WrongAsset | flow.PcapAssetID≠asset.ID | 404; "flow" | SIMULATED | |
| PCAP-GETFLOW-NEG3 | GetFlow requireReady | TestPcapGetFlow_NotReady | Status="importing" | 400 | SIMULATED | |
| PCAP-GETFLOW-BR1 | GetFlow 缺 :fid | TestPcapGetFlow_MissingFID | fid="" | 404; "flow" | SIMULATED | |
| PCAP-PKTS-FLOW-POS | ListPackets by flow | TestPcapListPacketsByFlow_Success | ready + flow | 200; {items,total,page,size} | SIMULATED | |
| PCAP-PKTS-FLOW-NEG1 | flow 不存在/他 asset | TestPcapListPacketsByFlow_NotFound | 随机 fid | 404; "flow" | SIMULATED | |
| PCAP-PKTS-FLOW-NEG2 | requireReady | TestPcapListPacketsByFlow_NotReady | Status="importing" | 400 | SIMULATED | |
| PCAP-PKTS-FLOW-BR1 | 分页 | TestPcapListPacketsByFlow_Pagination | page=0,size=501 | 200; page=1,size=50 | SIMULATED | |
| PCAP-PKTS-FLOW-NEG3 | repo 错 | TestPcapListPacketsByFlow_RepoError | 注入报错 | 500; "list packets:" | SIMULATED | |
| PCAP-STREAM-POS | GetStream c2s | TestPcapGetStream_C2S | ready + TCP flow 有 c2s | 200; octet-stream; 字节==.payloads[C2SOffset:C2SOffset+C2SLength] | SIMULATED | |
| PCAP-STREAM-BR1 | GetStream s2c | TestPcapGetStream_S2C | dir=s2c | 200; 对应 s2c 字节 | SIMULATED | |
| PCAP-STREAM-NEG1 | dir 非法 | TestPcapGetStream_BadDir | dir=both | 400; "dir must be c2s or s2c" | SIMULATED | |
| PCAP-STREAM-BR2 | stream 长度 0 | TestPcapGetStream_Empty | C2SLength=0 或 PayloadsPath="" | 200; 空字节 | SIMULATED | |
| PCAP-STREAM-BR3 | offset+limit 范围 | TestPcapGetStream_Range | offset=5,limit=10 | 200; 子集字节 | SIMULATED | |
| PCAP-STREAM-NEG2 | open payloads 错 | TestPcapGetStream_OpenFail | PayloadsPath 设但文件缺失 | 500; "open payloads:" | SIMULATED | |
| PCAP-STREAM-NEG3 | ReadAt 错 | TestPcapGetStream_ReadFail | offset 越界 | 500; "read stream:" | SIMULATED | |
| PCAP-STREAM-NEG4 | requireReady | TestPcapGetStream_NotReady | Status="importing" | 400 | SIMULATED | |
| PCAP-STREAM-NEG5 | flow 不存在 | TestPcapGetFlow_StreamFlowNotFound | 随机 fid | 404; "flow" | SIMULATED | |
| PCAP-BODY-POS | GetBody c2s | TestPcapGetBody_C2S | ready + TCP body | 200; octet-stream; 字节==.payloads[C2SOffset+C2SBodyOffset:...] | SIMULATED | |
| PCAP-BODY-BR1 | GetBody s2c | TestPcapGetBody_S2C | dir=s2c | 200; s2c body | SIMULATED | |
| PCAP-BODY-NEG1 | dir 非法 | TestPcapGetBody_BadDir | dir=x | 400; "dir must be c2s or s2c" | SIMULATED | |
| PCAP-BODY-BR2 | body 长度 0 | TestPcapGetBody_Empty | C2SBodyLength=0 | 200; 空 | SIMULATED | |
| PCAP-BODY-NEG2 | open/read 错 | TestPcapGetBody_ReadFail | 文件缺失/越界 | 500 | SIMULATED | |
| PCAP-BODY-NEG3 | requireReady | TestPcapGetBody_NotReady | Status="importing" | 400 | SIMULATED | |
| PCAP-BODY-NEG4 | flow 不存在 | TestPcapGetBody_FlowNotFound | 随机 fid | 404; "flow" | SIMULATED | |
| PCAP-PKTS-ASSET-POS | ListPacketsByAsset | TestPcapListPacketsByAsset_Success | ready | 200; {items,total,page,size}; 按捕获时间序 | SIMULATED | |
| PCAP-PKTS-ASSET-NEG1 | requireReady | TestPcapListPacketsByAsset_NotReady | Status="importing" | 400 | SIMULATED | |
| PCAP-PKTS-ASSET-BR1 | 分页 | TestPcapListPacketsByAsset_Pagination | page=0,size=501 | 200; page=1,size=50 | SIMULATED | |
| PCAP-PKTS-ASSET-NEG2 | repo 错 | TestPcapListPacketsByAsset_RepoError | 注入报错 | 500; "list packets:" | SIMULATED | |
| PCAP-GETPKT-POS | GetPacket 重解析 | TestPcapGetPacket_Success | ready + packet | 200; {packet,layers}; layers 含各层字段 | SIMULATED | |
| PCAP-GETPKT-NEG1 | packet 不存在/他 asset | TestPcapGetPacket_NotFound | 随机 pid | 404; "packet" | SIMULATED | |
| PCAP-GETPKT-NEG2 | 重解析错 | TestPcapGetPacket_ReparseFail | 使 ParsePacket 报错 | 500; "re-parse packet:" | SIMULATED | |
| PCAP-GETPKT-NEG3 | requireReady | TestPcapGetPacket_NotReady | Status="importing" | 400 | SIMULATED | |
| PCAP-PKTPAYLOAD-POS | GetPacketPayload | TestPcapPacketPayload_Success | ready + UDP packet + OffsetLayout.L4Start>=0 | 200; octet-stream; 字节==pcap[RawOffset:Length][L4Start+8:] | SIMULATED | |
| PCAP-PKTPAYLOAD-BR1 | 无 OffsetLayout | TestPcapPacketPayload_NoLayout | OffsetLayout="" / L4Start<0 | 200; 返回完整包字节（headerLen=0） | SIMULATED | |
| PCAP-PKTPAYLOAD-NEG1 | packet 不存在 | TestPcapPacketPayload_NotFound | 随机 pid | 404; "packet" | SIMULATED | |
| PCAP-PKTPAYLOAD-NEG2 | flow 不存在 | TestPcapPacketPayload_FlowNotFound | GetFlow 报错 | 404; "flow" | SIMULATED | |
| PCAP-PKTPAYLOAD-NEG3 | open pcap 错 | TestPcapPacketPayload_OpenFail | StoragePath 缺失 | 500; "open pcap:" | SIMULATED | |
| PCAP-PKTPAYLOAD-NEG4 | ReadAt 错 | TestPcapPacketPayload_ReadFail | RawOffset 越界 | 500; "read packet:" | SIMULATED | |
| PCAP-PKTPAYLOAD-NEG5 | requireReady | TestPcapPacketPayload_NotReady | Status="importing" | 400 | SIMULATED | |
| PCAP-SEARCH-POS | Search flow_filter | TestPcapSearch_FlowFilter | ready + flow_filter 匹配 | 200; results 含匹配 flow | SIMULATED | |
| PCAP-SEARCH-BR1 | Search packet_filter | TestPcapSearch_PacketFilter | packet_filter 设 | 200; 加载 packets 过滤 | SIMULATED | |
| PCAP-SEARCH-BR2 | Search payload | TestPcapSearch_Payload | payload filter + TCP 流 | 200; trigram 命中 | SIMULATED | |
| PCAP-SEARCH-NEG1 | Search 畸形 JSON | TestPcapSearch_BadJSON | "x" | 400; "invalid query:" | SIMULATED | |
| PCAP-SEARCH-NEG2 | Search 返错 | TestPcapSearch_SearchError | 使 Search 报错 | 400; "search:" | SIMULATED | |
| PCAP-SEARCH-NEG3 | load flows DB 错 | TestPcapSearch_LoadFlowsFail | 破坏 DB | 500; "load flows:" | SIMULATED | |
| PCAP-SEARCH-NEG4 | load packets DB 错 | TestPcapSearch_LoadPacketsFail | packet_filter + 破坏 DB | 500; "load packets:" | SIMULATED | |
| PCAP-SEARCH-BR3 | open payloads 错被吞 | TestPcapSearch_PayloadOpenFail | PayloadsPath 设但缺失 | 200; 静默跳过 payload 索引（err==nil 守卫） | SIMULATED | 记录: 静默降级 |
| PCAP-SEARCH-NEG5 | requireReady | TestPcapSearch_NotReady | Status="importing" | 400 | SIMULATED | |
| PCAP-MATCH-POS | MatchPreview 命中 | TestPcapMatchPreview_Hits | ready + matcher | 200; {flow_ids,count}; count=命中数 | SIMULATED | |
| PCAP-MATCH-NEG1 | matcher 畸形 | TestPcapMatchPreview_BadJSON | "x" | 400; "invalid matcher:" | SIMULATED | |
| PCAP-MATCH-NEG2 | ListFlows 错 | TestPcapMatchPreview_ListFlowsFail | 注入报错 | 500; "load flows:" | SIMULATED | |
| PCAP-MATCH-NEG3 | requireReady | TestPcapMatchPreview_NotReady | Status="importing" | 400 | SIMULATED | |
| PCAP-EXTRACT-POS | Extract 字段 | TestPcapExtract_Success | ready + packet_ids + fields | 200; {items:[{packet_id,fields:{src_ip:...}}]} | SIMULATED | |
| PCAP-EXTRACT-BR1 | Extract packet 不存在 | TestPcapExtract_PacketNotFound | 含不存在 pid | 200; items 含 {packet_id,error:"not found"} | SIMULATED | |
| PCAP-EXTRACT-BR2 | Extract 解析错 | TestPcapExtract_ParseError | 使 ParsePacket 报错 | 200; items 含 {packet_id,error:...} | SIMULATED | |
| PCAP-EXTRACT-NEG1 | Extract 畸形 JSON | TestPcapExtract_BadJSON | "x" | 400; "invalid extract request:" | SIMULATED | |
| PCAP-EXTRACT-NEG2 | Extract 空 packet_ids | TestPcapExtract_EmptyIDs | packet_ids=[] | 400; "packet_ids required" | SIMULATED | |
| PCAP-EXTRACT-NEG3 | Extract 过多 | TestPcapExtract_TooManyIDs | 501 个 pid | 400; "too many packet_ids (max 500)" | SIMULATED | |
| PCAP-EXTRACT-NEG4 | requireReady | TestPcapExtract_NotReady | Status="importing" | 400 | SIMULATED | |
| PCAP-DL-POS | Download | TestPcapDownload_Success | ready | 200; Content-Disposition 含 OriginalFilename; body==文件内容 | SIMULATED | |
| PCAP-DL-NEG1 | requireReady | TestPcapDownload_NotReady | Status="importing" | 400 | SIMULATED | |
| PCAP-DL-NEG2 | 文件缺失 | TestPcapDownload_FileMissing | StoragePath 文件删 | 404（gin FileAttachment） | SIMULATED | |
| PCAP-REPARSE-POS | Reparse 成功 | TestPcapReparse_Success | ready asset | 200; "reparse complete"; data.Status="ready"; FlowCount/PacketCount 更新; 旧 flows/packets 替换; .payloads 重建 | SIMULATED | |
| PCAP-REPARSE-NEG1 | 已 reindexing | TestPcapReparse_AlreadyReindexing | Status="reindexing" | 400; "asset is already reindexing" | SIMULATED | |
| PCAP-REPARSE-NEG2 | Reparse 错 | TestPcapReparse_ReparseFail | 使 Reparse 报错 | 500; "reparse:"; asset.Status="error" | SIMULATED | |
| PCAP-REPARSE-NEG3 | CreateFlows 错 | TestPcapReparse_CreateFlowsFail | 注入报错 | 500; "store flows:"; Status="error" | SIMULATED | |
| PCAP-REPARSE-NEG4 | CreatePackets 错 | TestPcapReparse_CreatePacketsFail | 注入报错 | 500; "store packets:"; Status="error" | SIMULATED | |
| PCAP-REPARSE-BR1 | importing 状态 Reparse | TestPcapReparse_ImportingIgnoredError | Status="importing" | UpdateAssetStatus 返 "illegal transition" 但 handler 忽略; 继续执行 Reparse（记录: 忽略状态机错误） | SIMULATED | 记录潜在 bug |
| PCAP-REPARSE-BR2 | 先删旧 flows/packets | TestPcapReparse_DeleteBeforeParse | ready | 200; 旧 flows/packets 在 Reparse 前删（避免脏数据） | SIMULATED | |
| PCAP-REPARSE-BR3 | 无 requireReady 门 | TestPcapReparse_NoReadyGate | Status="error" | 200（非 400; Reparse 不调 requireReady, 允许 error 状态） | SIMULATED | |

## 组件: Server (server.go) - 路由注册/Setup/CORS/接口处理/listPorts

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| SRV-ROUTE-POS | R1-Rxx 路由注册 | TestServerSetup_RoutesRegistered | cfg 默认 + mock 引擎/DB + wsHandler | 每个端点可达（非 404 NoRoute）; 公开端点无 token 200; 受保护端点无 token 401 | SIMULATED | 表驱动遍历路由表 |
| SRV-BR1 | SR1 release 模式 | TestServerSetup_ReleaseMode | cfg.Server.Mode="release" | gin.Mode()==ReleaseMode | SIMULATED | |
| SRV-BR2 | SR2 test 模式 | TestServerSetup_TestMode | Mode="test" | gin.Mode()==TestMode | SIMULATED | |
| SRV-BR3 | SR3 默认 debug | TestServerSetup_DebugMode | Mode="" | gin.Mode()==DebugMode | SIMULATED | |
| SRV-BR4 | SR4 wsHandler 设 | TestServerSetup_WSRegistered | wsHandler≠nil | GET /ws 路由存在（非 404） | SIMULATED | |
| SRV-BR5 | SR5 wsHandler nil | TestServerSetup_WSNotRegistered | wsHandler=nil | GET /ws -> 404 NoRoute | SIMULATED | |
| SRV-BR6 | SR6 metrics 开 | TestServerSetup_MetricsEnabled | Metrics.Enabled=true | GET <path> -> 200 prometheus | SIMULATED | |
| SRV-BR7 | SR7 metrics 关 | TestServerSetup_MetricsDisabled | Metrics.Enabled=false | GET <path> -> 404 | SIMULATED | |
| SRV-BR8 | SPA NoRoute fallback | TestServerSetup_SPAFallback | chdir 到含 web/dist/index.html 的 temp | GET /random/route -> 200; body 含 index.html | SIMULATED | 需建 ./web/dist/index.html |
| SRV-BR9 | /assets 静态 | TestServerSetup_StaticAssets | 建 web/dist/assets/x.js | GET /assets/x.js -> 200 | SIMULATED | |
| CORS-BR1 | C1 origin 空 | TestCORS_EmptyOrigin | 无 Origin 头 | 200; 无 ACAO 头; 请求继续 | SIMULATED | |
| CORS-BR2 | C2 origin 在白名单 | TestCORS_AllowedOrigin | Origin="https://app.example.com"（白名单内） | 200; ACAO=该 origin; ACACredentials=true | SIMULATED | |
| CORS-BR3 | C2 通配 "*" | TestCORS_Wildcard | AllowedOrigins=["*"], Origin="https://x.com" | 200; ACAO=Origin（非 "*"，代码设为 origin） | SIMULATED | 记录: 设为 origin 非 * |
| CORS-BR4 | C3 origin 不在白名单 | TestCORS_NotAllowed | Origin="https://evil.com" | 200; 无 ACAO 头; 请求仍继续（不 abort） | SIMULATED | |
| CORS-BR5 | C4 OPTIONS 预检 | TestCORS_Preflight | OPTIONS + Origin | 204; 含 ACAO/ACAMethods/ACAHeaders | SIMULATED | |
| CORS-BR6 | 所有 CORS 头齐全 | TestCORS_AllHeaders | 白名单 origin | ACAOrigin/ACACredentials/ACAHeaders/ACAMethods 全设 | SIMULATED | |
| IFACE-BR1 | I1 ifaceMgr nil | TestListInterfaces_NilMgr | s.ifaceMgr=nil | 200; data=[] | SIMULATED | |
| IFACE-BR2 | I2 portSched nil | TestListInterfaces_NilSched | portSched=nil | 200; InUse=false; Allocations 空 | SIMULATED | |
| IFACE-BR3 | I4 列接口含字段 | TestListInterfaces_Fields | mock ifaceMgr.List 返回接口 | 200; data 含 name/mac/ips/is_up/link_up/mtu/description/is_virtual/in_use/allocations | SIMULATED | 需可注入 ifaceMgr（建议抽 interface） |
| IFACE-NEG1 | I3 Refresh 错 | TestDiscoverInterfaces_RefreshFail | mock Refresh 报错 | 500; "failed to discover interfaces:" | SIMULATED | 需可注入 ifaceMgr |
| IFACE-BR4 | ifaceMgr nil 时 discover | TestDiscoverInterfaces_NilMgr | s.ifaceMgr=nil | 500; "interface manager not initialized" | SIMULATED | |
| PORTS-LIST-POS | LP1 列端口 | TestListPorts_Success | DB 有 PortModel | 200; data 含 id/name/type/pci_address/status/current_task_id/created_at/updated_at | SIMULATED | |
| PORTS-LIST-NEG1 | LP2 DB Find 错 | TestListPorts_DBFindFail | 破坏 DB | 500; "failed to list ports:" | SIMULATED | |
| PORTS-LIST-BR1 | 公开无需鉴权 | TestListPorts_Public | 无 token | 200（非 401） | SIMULATED | |

## 组件: Server - MANUAL（真实外部监听/真实内核）

| 测试点ID | 覆盖场景 | 测试函数名 | 输入 | 断言(可观测) | 类型 | 备注 |
|---|---|---|---|---|---|---|
| SRV-START-MANUAL | Server.Start 真实监听 | (手动) | 真实 cfg + 真实引擎 + 真实 DB; `Server.Start()` 绑定真实 TCP 端口 | curl http://host:port/health -> 200 {"status":"healthy"}; 真实 ReadTimeout/WriteTimeout/IdleTimeout 生效; `Shutdown(ctx)` 优雅排空在途请求 | MANUAL | 为何无法自动: httptest 是进程内,跳过真实 TCP/超时/优雅关闭排空. 命令: `./trafficgen -config prod.yaml &` 然后 `curl -s http://127.0.0.1:8080/health`; `kill -TERM <pid>` 观察日志 "shutting down" + 在途请求完成. 预期: 健康检查 200; SIGTERM 后 0 残留连接 |
| AUTH-REALSERVER-MANUAL | 真实鉴权中间件端到端 | (手动) | 真实服务器 + 真实 JWT secret + 真实 token DB; register->login->用 Bearer 调受保护端点 | `curl -X POST /auth/register` -> 201; `curl -X POST /auth/login` -> 200 拿 token; `curl -H "Authorization: Bearer <token>" /api/v1/user/profile` -> 200; DB tokens 表有 active 行; logout 后同 token 再调 -> 401 "token has been revoked" | MANUAL | 为何无法自动: 真实中间件链跑在真实监听服务器上、真实网络往返、真实 token DB 行生命周期, 与 httptest 隔离测试不同. 命令: 见上, 用 curl 带 -H Authorization. 预期: token 签发/校验/撤销全链路通过真实 TCP |
| IFACE-DISCOVER-MANUAL | 真实接口发现 | (手动) | 真实 netif.Manager 枚举主机内核 NIC | `curl -X POST /api/v1/interfaces/discover` -> 200 {"message":"discovery completed","data":{"count":N}}; N 与 `ip -j link show | jq length` 一致; GET /api/v1/interfaces 返回的 name 集合 ⊆ `ip -o link show` 输出 | MANUAL | 为何无法自动: netif.Manager 是具体 struct 非接口, 不可注入; Refresh 走 netlink/ioctl 枚举真实内核接口. 命令: `curl -s http://127.0.0.1:8080/api/v1/interfaces | jq '.data[].name'` 对比 `ip -o link show | awk -F': ' '{print $2}'`. 预期: 物理网卡(如 enp135s0f0np0)/lo/虚拟接口均出现 |

> 外部 IdP（OIDC/SAML）集成: 当前代码仅本地 JWT + DB token store, 无外部 IdP 集成代码, 故不设外部 IdP MANUAL 测试点。若未来接入外部签发者, 其真实对接（discovery/jwks 拉取/claim 映射）应另立 MANUAL 点。

## 汇总

- 真实(REAL): 30 个
  - hashToken(3) + validateIP(7) + validateMAC(6) + validateConfigNetwork(9) + calculateConfigHash(1) + calculatePortsConfigHash(1) + calculateTaskHash(1) + layersLinkType(1) + currentTime(1)
- 模拟(SIMULATED): 497 个
  - resolvePcapPath(8) + 中间件 M1-M8(11) + MWGATE 参数化(4) + 用户隔离 ISO(32) + AUTH(73) + STRAT(66) + TASK(126) + PORT(26) + SYS(18) + PCAP(109) + SERVER(24 = SRV 10 + CORS 6 + IFACE 5 + PORTS 3)
- 手动(MANUAL): 3 个
  - SRV-START-MANUAL / AUTH-REALSERVER-MANUAL / IFACE-DISCOVER-MANUAL
- 合计: 530 个测试点

### MANUAL 测试点清单（ID + 一句话原因）
1. **SRV-START-MANUAL** — `Server.Start()` 调真实 `ListenAndServe` 绑定真实 TCP 端口，httptest 是进程内无法验证真实 TCP I/O / 超时 / 优雅 Shutdown 排空。
2. **AUTH-REALSERVER-MANUAL** — 真实鉴权中间件 + 真实 JWT/secret + 真实 token DB 跑在真实监听服务器上的 register→login→受保护端点→logout 全链路，与 httptest 隔离测试不同，须真实网络往返。
3. **IFACE-DISCOVER-MANUAL** — `netif.Manager` 是具体 struct 非 interface 不可注入，`Refresh()` 走 netlink/ioctl 枚举主机真实内核 NIC，结果依赖物理/虚拟接口。

> 外部 IdP（OIDC/SAML）集成: 当前代码仅本地 JWT + DB token store, 无外部 IdP 代码, 故不设外部 IdP MANUAL 点; 若未来接入外部签发者, 其 discovery/jwks/claim 映射真实对接应另立 MANUAL 点。

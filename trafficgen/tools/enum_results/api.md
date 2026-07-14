Now I have all the complete source code. Let me compile the exhaustive enumeration.

---

# Complete Business Scenario Enumeration: REST API Handlers

---

## AUTH HANDLER -- `/home/weihang/trafficGenerator/trafficgen/internal/api/rest/auth_handler.go`

**Middleware gating all `/api/v1/*` authenticated routes (AuthMiddlewareWithDB from `/home/weihang/trafficGenerator/trafficgen/pkg/auth/middleware.go`):**

Note: All handlers in the `/api/v1` group pass through `AuthMiddlewareWithDB` BEFORE reaching handler code. The middleware checks (applied to ALL endpoints AUTH2-AUTH12 below):

| Step | Branch | Status | Response |
|------|--------|--------|----------|
| M1 | No `Authorization` header | 401 | `{"code":401,"message":"missing authorization header"}` |
| M2 | Not `Bearer <token>` format | 401 | `{"code":401,"message":"invalid authorization header format"}` |
| M3 | JWT parse/validate fails | 401 | `{"code":401,"message":"invalid or expired token"}` |
| M4 | Token hash not in DB (`ErrRecordNotFound`) | 401 | `{"code":401,"message":"token not recognized"}` |
| M5 | DB query error fetching token record | 500 | `{"code":500,"message":"failed to validate token"}` |
| M6 | Token status != "active" | 401 | `{"code":401,"message":"token has been revoked"}` |
| M7 | `time.Now().After(tokenRecord.ExpiresAt)` | 401 | `{"code":401,"message":"token has expired"}` |
| M8 | All checks pass | passes | Stores `userID`, `username`, `roles` in context, calls `c.Next()` |

---

### AUTH1: POST /api/v1/auth/register -- Register

| # | Scenario | Logical Branch | Status | Response |
|---|----------|----------------|--------|----------|
| A1.1 | Valid registration | All checks pass, db.Create succeeds | **201** | `{"code":0,"message":"created","data":{"user_id":"...","username":"...","email":"..."}}` |
| A1.2 | Invalid JSON payload | `c.ShouldBindJSON(&req)` returns error | **400** | `{"code":400,"message":"invalid request: ..."}` |
| A1.3 | Username validation fails | binding tag `min=3,max=64` fails | **400** | (caught by A1.2 branch) |
| A1.4 | Password validation fails | binding tag `min=8,max=128` fails | **400** | (caught by A1.2 branch) |
| A1.5 | Email validation fails | binding tag `email` fails | **400** | (caught by A1.2 branch) |
| A1.6 | Username already exists | `h.db.Where("username = ?").First` succeeds (err==nil) | **400** | `{"code":400,"message":"username already exists"}` |
| A1.7 | Email already exists | `h.db.Where("email = ?").First` succeeds (err==nil) | **400** | `{"code":400,"message":"email already exists"}` |
| A1.8 | Password hashing fails | `auth.HashPassword(req.Password)` returns error | **500** | `{"code":500,"message":"failed to hash password"}` |
| A1.9 | DB create user fails | `h.db.Create(user).Error` != nil | **500** | `{"code":500,"message":"failed to create user: ..."}` |
| A1.10 | Duplicate username and email conflict | Both A1.6 and A1.7 match | **400** | First check (username) wins |

---

### AUTH2: POST /api/v1/auth/login -- Login (no auth middleware)

| # | Scenario | Logical Branch | Status | Response |
|---|----------|----------------|--------|----------|
| A2.1 | Valid credentials | All checks pass | **200** | `{"code":0,"message":"success","data":{"token":"...","expires_at":...,"user_id":"...","username":"..."}}` |
| A2.2 | Invalid JSON payload | `c.ShouldBindJSON(&req)` error | **400** | `{"code":400,"message":"invalid request: ..."}` |
| A2.3 | Username not found | `gorm.ErrRecordNotFound` | **401** | `{"code":401,"message":"invalid credentials"}` (generic to prevent user enumeration) |
| A2.4 | DB query error (non-NotFound) | `err != nil` and `err != gorm.ErrRecordNotFound` | **500** | `{"code":500,"message":"failed to query user"}` |
| A2.5 | User is disabled | `!user.Enabled` | **401** | `{"code":401,"message":"user is disabled"}` |
| A2.6 | Wrong password | `!auth.CheckPassword(req.Password, user.PasswordHash)` | **401** | `{"code":401,"message":"invalid credentials"}` |
| A2.7 | JWT generation fails | `h.jwtManager.GenerateToken(...)` error | **500** | `{"code":500,"message":"failed to generate token"}` |
| A2.8 | Token hash collision (same hash exists) | `h.db.Where("token_hash = ?").First` succeeds → deletes old record | **200** | Silently cleans up duplicate, then continues to create new token |
| A2.9 | DB create token record fails | `h.db.Create(tokenRecord).Error` != nil | **500** | `{"code":500,"message":"failed to store token"}` |
| A2.10 | DB update last_login_at fails | `h.db.Model(&user).Update(...)` returns error (unchecked) | **200** | Success despite DB update failure (silent degradation) |

---

### AUTH3: GET /api/v1/auth/validate -- Validate Token (no auth middleware)

| # | Scenario | Logical Branch | Status | Response |
|---|----------|----------------|--------|----------|
| A3.1 | Valid token | All checks pass | **200** | `{"code":0,"message":"success","data":{"valid":true,"user_id":"...","username":"...","roles":[...]}}` |
| A3.2 | Missing Authorization header | `authHeader == ""` | **400** | `{"code":400,"message":"missing authorization header"}` |
| A3.3 | Invalid header format (not Bearer) | `len(authHeader) <= 7` or prefix mismatch | **400** | `{"code":400,"message":"invalid authorization header format"}` |
| A3.4 | JWT invalid/expired | `h.jwtManager.ValidateToken(tokenString)` error | **401** | `{"code":401,"message":"invalid or expired token"}` |
| A3.5 | Token not in DB | `gorm.ErrRecordNotFound` | **401** | `{"code":401,"message":"token not found"}` |
| A3.6 | DB query error | Other `err != nil` | **500** | `{"code":500,"message":"failed to query token"}` |
| A3.7 | Token is revoked | `tokenRecord.Status != "active"` | **401** | `{"code":401,"message":"token is revoked"}` |
| A3.8 | Token is expired | `time.Now().After(tokenRecord.ExpiresAt)` | **401** | `{"code":401,"message":"token is expired"}` |

---

### AUTH4: POST /api/v1/auth/logout -- Logout (no auth middleware)

| # | Scenario | Logical Branch | Status | Response |
|---|----------|----------------|--------|----------|
| A4.1 | No auth header (already logged out) | `authHeader == ""` | **200** | `{"code":0,"message":"logged out","data":null}` (graceful no-op) |
| A4.2 | Invalid header format (not Bearer) | `len(authHeader) <= 7` or prefix mismatch | **200** | `{"code":0,"message":"logged out","data":null}` (tokenString stays "", no-op) |
| A4.3 | Valid token, revoke succeeds | All branches pass | **200** | `{"code":0,"message":"logged out","data":null}` |
| A4.4 | Valid token, DB update fails | `h.db.Model(...).Update(...)` error (unchecked) | **200** | Success despite revoke failure (silent degradation) |
| A4.5 | Token not in DB (already revoked or tampered) | Update matches 0 rows | **200** | Success (silent no-op) |

---

### AUTH5: POST /api/v1/auth/refresh -- Refresh Token (authenticated)

| # | Scenario | Logical Branch | Status | Response |
|---|----------|----------------|--------|----------|
| A5.1 | Valid refresh | All checks pass | **200** | `{"code":0,"message":"success","data":{"token":"...","expires_at":...,"user_id":"...","username":"..."}}` |
| A5.2 | No user in context | `auth.GetUserID(c)` returns "" (redundant with middleware) | **401** | `{"code":401,"message":"invalid token"}` |
| A5.3 | GenerateToken fails | `h.jwtManager.GenerateToken(...)` error | **500** | `{"code":500,"message":"failed to generate token"}` |
| A5.4 | Old token revocation (valid Bearer) | `len(authHeader)>7 && prefix match` → updates old hash to revoked | **200** | Silently revokes old token, continues |
| A5.5 | Old token revocation skipped (not Bearer) | Header format check fails | **200** | Skips revocation, generates new token without revoking old |
| A5.6 | DB create new token record fails | `h.db.Create(tokenRecord).Error` != nil | **500** | `{"code":500,"message":"failed to store token"}` |

---

### AUTH6: GET /api/v1/user/profile -- Get Profile (authenticated)

| # | Scenario | Logical Branch | Status | Response |
|---|----------|----------------|--------|----------|
| A6.1 | Profile found | All checks pass | **200** | User profile data |
| A6.2 | No user in context | `auth.GetUserID(c)` returns "" | **401** | `{"code":401,"message":"user not authenticated"}` |
| A6.3 | User not in DB | `gorm.ErrRecordNotFound` | **404** | `{"code":404,"message":"user not found"}` |
| A6.4 | DB query error | Other error from `h.db.Where("id = ?").First` | **500** | `{"code":500,"message":"failed to query user"}` |

---

### AUTH7: PUT /api/v1/user/profile -- Update Profile (authenticated)

| # | Scenario | Logical Branch | Status | Response |
|---|----------|----------------|--------|----------|
| A7.1 | Update email only | Email changes, password empty, updates success | **200** | `{"code":0,"message":"profile updated","data":null}` |
| A7.2 | Update password only | Password provided, email unchanged, updates success | **200** | `{"code":0,"message":"profile updated","data":null}` |
| A7.3 | Update both email and password | Both provided, all validation passes | **200** | `{"code":0,"message":"profile updated","data":null}` |
| A7.4 | No changes submitted | Both email and password empty | **200** | `{"code":0,"message":"profile updated","data":null}` (no-op, `len(updates)==0` skips DB write) |
| A7.5 | No user in context | `auth.GetUserID(c)` returns "" | **401** | `{"code":401,"message":"user not authenticated"}` |
| A7.6 | User not in DB | `gorm.ErrRecordNotFound` | **404** | `{"code":404,"message":"user not found"}` |
| A7.7 | DB query error | Other error fetching user | **500** | `{"code":500,"message":"failed to query user"}` |
| A7.8 | User is admin | `user.Role == "admin"` | **403** | `{"code":403,"message":"admin account cannot be modified via API"}` |
| A7.9 | Invalid JSON payload | `c.ShouldBindJSON(&req)` error | **400** | `{"code":400,"message":"invalid request: ..."}` |
| A7.10 | Invalid email format | binding `email` fails | **400** | (caught by A7.9) |
| A7.11 | Password too short (<8) | binding `min=8` fails | **400** | (caught by A7.9) |
| A7.12 | New email already taken by another user | `h.db.Where("email = ? AND id != ?", ...).First` succeeds | **400** | `{"code":400,"message":"email already exists"}` |
| A7.13 | Password hashing fails | `auth.HashPassword(req.Password)` error | **500** | `{"code":500,"message":"failed to hash password"}` |
| A7.14 | DB update fails | `h.db.Model(&user).Updates(updates).Error` != nil | **500** | `{"code":500,"message":"failed to update profile"}` |

---

### AUTH8: DELETE /api/v1/user/profile -- Delete Profile (authenticated)

| # | Scenario | Logical Branch | Status | Response |
|---|----------|----------------|--------|----------|
| A8.1 | Regular user deletes own account | All checks pass | **200** | `{"code":0,"message":"account deleted","data":null}` |
| A8.2 | No user in context | `auth.GetUserID(c)` returns "" | **401** | `{"code":401,"message":"user not authenticated"}` |
| A8.3 | User not in DB | `gorm.ErrRecordNotFound` | **404** | `{"code":404,"message":"user not found"}` |
| A8.4 | DB query error | Other error fetching user | **500** | `{"code":500,"message":"failed to query user"}` |
| A8.5 | User is admin | `user.Role == "admin"` | **403** | `{"code":403,"message":"admin account cannot be deleted via API"}` |
| A8.6 | Token revocation fails | `h.db.Model(...).Update("status","revoked")` error (unchecked) | **200** | Account deleted despite token revocation failure (silent degradation) |
| A8.7 | DB delete fails | `h.db.Delete(&user).Error` != nil | **500** | `{"code":500,"message":"failed to delete account"}` |

---

## STRATEGY HANDLER -- `/home/weihang/trafficGenerator/trafficgen/internal/api/rest/strategy_handler.go`

### STRAT1: POST /api/v1/strategies -- Create Strategy (authenticated)

| # | Scenario | Logical Branch | Status | Response |
|---|----------|----------------|--------|----------|
| S1.1 | New strategy, all valid | All checks pass | **201** | `{"code":0,"message":"created","data":{"id":"..."}}` |
| S1.2 | No user in context | `auth.GetUserID(c)` returns "" | **401** | `{"code":401,"message":"user not authenticated"}` |
| S1.3 | Invalid JSON payload | `c.ShouldBindJSON(&req)` error | **400** | `{"code":400,"message":"invalid request: ..."}` |
| S1.4 | Missing required field `name` | binding `required` fails | **400** | (caught by S1.3) |
| S1.5 | Missing required field `protocol` | binding `required` fails | **400** | (caught by S1.3) |
| S1.6 | Missing required field `config` | binding `required` fails | **400** | (caught by S1.3) |
| S1.7 | Invalid IP in config (src_ip/dst_ip) | `validateConfigNetwork` returns error | **400** | `{"code":400,"message":"invalid IP format: src_ip = ..."}` |
| S1.8 | Invalid MAC in config (src_mac/dst_mac) | `validateConfigNetwork` returns error | **400** | `{"code":400,"message":"invalid MAC format: src_mac = ..."}` |
| S1.9 | Value out of range (dscp>255, vlan>4095, etc.) | `core.ValidateConfigRanges` returns error | **400** | Range validation error message |
| S1.10 | Empty protocol string | `req.Protocol == ""` | **400** | `{"code":400,"message":"invalid or missing protocol: "}` |
| S1.11 | Unsupported protocol (e.g. "sctp") | `!validProtocols[req.Protocol]` | **400** | `{"code":400,"message":"invalid or missing protocol: sctp"}` |
| S1.12 | Invalid protocol sub-config | `core.ValidateProtocolSubConfigs` returns error | **400** | Sub-config validation error message |
| S1.13 | FlowControl not provided | `req.FlowControl == nil` | **201** | Default flow control: type="flows", value=1 |
| S1.14 | Invalid flow_control type | `!validFlowTypes[req.FlowControl.Type]` | **400** | `{"code":400,"message":"invalid flow_control type: must be flows, cps, bps, ratio, or time"}` |
| S1.15 | flow_control value <= 0 | `req.FlowControl.Value <= 0` | **400** | `{"code":400,"message":"flow_control value must be positive"}` |
| S1.16 | Config JSON serialization fails | `json.Marshal(req.Config)` error | **400** | `{"code":400,"message":"invalid config format"}` |
| S1.17 | FlowControl JSON serialization fails | `json.Marshal(req.FlowControl)` error | **400** | `{"code":400,"message":"invalid flow_control format"}` |
| S1.18 | Duplicate strategy (same hash) | Existing strategy found by config_hash | **200** | `{"code":0,"message":"success","data":{"id":"...","message":"strategy already exists"}}` |
| S1.19 | DB create fails | `h.db.Create(strategy).Error` != nil | **500** | `{"code":500,"message":"failed to create strategy: ..."}` |

---

### STRAT2: GET /api/v1/strategies -- List Strategies (authenticated)

| # | Scenario | Logical Branch | Status | Response |
|---|----------|----------------|--------|----------|
| S2.1 | User has strategies | DB returns results | **200** | Array of StrategyResponse with task counts |
| S2.2 | User has no strategies | DB returns empty | **200** | `[]` |
| S2.3 | No user in context | `auth.GetUserID(c)` returns "" | **401** | `{"code":401,"message":"user not authenticated"}` |
| S2.4 | DB query fails | `h.db.Where("user_id = ?").Find(&strategies).Error` != nil | **500** | `{"code":500,"message":"failed to list strategies: ..."}` |
| S2.5 | Config JSON deserialization fails | `json.Unmarshal([]byte(s.Config), &config)` error (unchecked) | **200** | config is nil in response (silent degradation) |
| S2.6 | FlowControl JSON deserialization fails | `json.Unmarshal([]byte(s.FlowControl), &flowControl)` error (unchecked) | **200** | flowControl is zero-value in response (silent degradation) |
| S2.7 | Task count query fails | `h.db.Model(&storage.TaskModel{}).Where(...).Count(&taskCount)` error (unchecked) | **200** | taskCount stays 0 (silent degradation) |

---

### STRAT3: GET /api/v1/strategies/:id -- Get Strategy (authenticated)

| # | Scenario | Logical Branch | Status | Response |
|---|----------|----------------|--------|----------|
| S3.1 | Strategy found and owned by user | DB returns result | **200** | StrategyResponse |
| S3.2 | No user in context | `auth.GetUserID(c)` returns "" | **401** | `{"code":401,"message":"user not authenticated"}` |
| S3.3 | Missing `:id` path param | `c.Param("id")` returns "" | **400** | `{"code":400,"message":"missing strategy id"}` |
| S3.4 | Strategy not found (wrong ID or not owned) | `gorm.ErrRecordNotFound` on user-scoped query | **404** | `{"code":404,"message":"strategy not found"}` |
| S3.5 | DB query error | Other error | **500** | `{"code":500,"message":"failed to get strategy: ..."}` |

---

### STRAT4: PUT /api/v1/strategies/:id -- Update Strategy (authenticated)

| # | Scenario | Logical Branch | Status | Response |
|---|----------|----------------|--------|----------|
| S4.1 | Strategy updated successfully | All checks pass, db.Save succeeds | **200** | `{"code":0,"message":"strategy updated","data":null}` |
| S4.2 | No user in context | `auth.GetUserID(c)` returns "" | **401** | `{"code":401,"message":"user not authenticated"}` |
| S4.3 | Missing `:id` path param | `c.Param("id")` returns "" | **400** | `{"code":400,"message":"missing strategy id"}` |
| S4.4 | Invalid JSON payload | `c.ShouldBindJSON(&req)` error | **400** | `{"code":400,"message":"invalid request: ..."}` |
| S4.5 | Invalid IP/MAC in config | `validateConfigNetwork` returns error | **400** | Validation error message |
| S4.6 | Value out of range | `core.ValidateConfigRanges` error | **400** | Range error message |
| S4.7 | Invalid protocol sub-config | `core.ValidateProtocolSubConfigs` error | **400** | Sub-config error message |
| S4.8 | Strategy not found (wrong ID or not owned) | `gorm.ErrRecordNotFound` on user-scoped query | **404** | `{"code":404,"message":"strategy not found"}` |
| S4.9 | DB query error | Other error finding strategy | **500** | `{"code":500,"message":"failed to get strategy: ..."}` |
| S4.10 | FlowControl provided with invalid type | `req.FlowControl != nil && !validFlowTypes[req.FlowControl.Type]` | **400** | `{"code":400,"message":"invalid flow_control type: must be flows, cps, bps, ratio, or time"}` |
| S4.11 | FlowControl value <= 0 | `req.FlowControl.Value <= 0` | **400** | `{"code":400,"message":"flow_control value must be positive"}` |
| S4.12 | FlowControl not provided (nil) | `req.FlowControl == nil` | **200** | Skips flow control validation, marshals nil |
| S4.13 | Config JSON serialization fails | `json.Marshal(req.Config)` error | **400** | `{"code":400,"message":"invalid config format"}` |
| S4.14 | FlowControl JSON serialization fails | `json.Marshal(req.FlowControl)` error | **400** | `{"code":400,"message":"invalid flow_control format"}` |
| S4.15 | DB save fails | `h.db.Save(&strategy).Error` != nil | **500** | `{"code":500,"message":"failed to update strategy: ..."}` |

---

### STRAT5: DELETE /api/v1/strategies/:id -- Delete Strategy (authenticated)

| # | Scenario | Logical Branch | Status | Response |
|---|----------|----------------|--------|----------|
| S5.1 | Strategy deleted successfully | Not referenced by any tasks, db.Delete succeeds | **200** | `{"code":0,"message":"strategy deleted","data":null}` |
| S5.2 | No user in context | `auth.GetUserID(c)` returns "" | **401** | `{"code":401,"message":"user not authenticated"}` |
| S5.3 | Missing `:id` path param | `c.Param("id")` returns "" | **400** | `{"code":400,"message":"missing strategy id"}` |
| S5.4 | Strategy not found (wrong ID or not owned) | `gorm.ErrRecordNotFound` on user-scoped query | **404** | `{"code":404,"message":"strategy not found"}` |
| S5.5 | DB query error | Other error finding strategy | **500** | `{"code":500,"message":"failed to get strategy: ..."}` |
| S5.6 | Strategy referenced by active tasks | `taskCount > 0` from JSON array search | **400** | `{"code":400,"message":"strategy is used by tasks, cannot delete"}` |
| S5.7 | DB delete fails | `h.db.Delete(&strategy).Error` != nil | **500** | `{"code":500,"message":"failed to delete strategy: ..."}` |

---

### STRAT6: GET /api/v1/strategies/:id/tasks -- List Strategy Tasks (authenticated)

| # | Scenario | Logical Branch | Status | Response |
|---|----------|----------------|--------|----------|
| S6.1 | Strategy has referencing tasks | Tasks found in DB | **200** | Array of TaskBrief |
| S6.2 | Strategy has no referencing tasks | No tasks found | **200** | `[]` |
| S6.3 | No user in context | `auth.GetUserID(c)` returns "" | **401** | `{"code":401,"message":"user not authenticated"}` |
| S6.4 | Missing `:id` path param | `c.Param("id")` returns "" | **400** | `{"code":400,"message":"missing strategy id"}` |
| S6.5 | Strategy not found (wrong ID or not owned) | `gorm.ErrRecordNotFound` on user-scoped query | **404** | `{"code":404,"message":"strategy not found"}` |
| S6.6 | DB query error finding strategy | Other error | **500** | `{"code":500,"message":"failed to get strategy: ..."}` |
| S6.7 | DB Find fails for tasks | `h.db.Where(...).Find(&tasks).Error` != nil (unchecked) | **200** | Empty result (silent degradation) |

---

## TASK HANDLER -- `/home/weihang/trafficGenerator/trafficgen/internal/api/rest/task_handler.go`

### TASK1: POST /api/v1/tasks -- Create Task (authenticated)

| # | Scenario | Logical Branch | Status | Response |
|---|----------|----------------|--------|----------|
| T1.1 | New task, all valid | All checks pass | **201** | `{"code":0,"message":"created","data":{"id":"..."}}` |
| T1.2 | No user in context | `auth.GetUserID(c)` returns "" | **401** | `{"code":401,"message":"user not authenticated"}` |
| T1.3 | Invalid JSON payload | `c.ShouldBindJSON(&req)` error | **400** | `{"code":400,"message":"invalid request: ..."}` |
| T1.4 | Missing required `name` | binding `required` | **400** | (caught by T1.3) |
| T1.5 | Empty strategy_ids | binding `min=1` OR `len(req.StrategyIDs) == 0` | **400** | `{"code":400,"message":"at least one strategy_id is required"}` |
| T1.6 | Port group output without PortGroupID | `req.OutputType == "port_group" && req.OutputConfig.PortGroupID == ""` | **400** | `{"code":400,"message":"port_group_id is required for port_group output"}` |
| T1.7 | PCAP output without PcapPath | `req.OutputType == "pcap" && req.OutputConfig.PcapPath == ""` | **400** | `{"code":400,"message":"pcap_path is required for pcap output"}` |
| T1.8 | Strategy ID not found (or not owned) | `gorm.ErrRecordNotFound` during validation | **400** | `{"code":400,"message":"strategy <id> not found"}` |
| T1.9 | DB query error validating strategy | Other error | **500** | `{"code":500,"message":"failed to validate strategy: ..."}` |
| T1.10 | Multiple strategies, first sets primary protocol | `primaryProtocol == ""` only set once | **201** | protocol = first strategy's protocol |
| T1.11 | Duplicate active task (same strategy_ids + output_config) | Idempotency check finds existing pending/running task | **200** | `{"code":0,"message":"success","data":{"id":"...","message":"task already exists"}}` |
| T1.12 | DB create task fails | `h.db.Create(task).Error` != nil | **500** | `{"code":500,"message":"failed to create task: ..."}` |
| T1.13 | FlowControl not provided | `req.FlowControl == nil` | **201** | flowControlJSON stays nil/empty |

---

### TASK2: POST /api/v1/tasks/batch -- Create Batch Task (authenticated)

| # | Scenario | Logical Branch | Status | Response |
|---|----------|----------------|--------|----------|
| T2.1 | Valid batch, port_group output | All checks pass | **201** | `{"code":0,"message":"created","data":{"id":"..."}}` |
| T2.2 | Valid batch, pcap output | All checks pass | **201** | `{"code":0,"message":"created","data":{"id":"..."}}` |
| T2.3 | No user in context | `auth.GetUserID(c)` returns "" | **401** | `{"code":401,"message":"user not authenticated"}` |
| T2.4 | Invalid JSON payload | `c.ShouldBindJSON(&req)` error | **400** | `{"code":400,"message":"invalid request: ..."}` |
| T2.5 | Batch spec nil or empty classes | `req.Batch == nil \|\| len(req.Batch.Classes) == 0` | **400** | `{"code":400,"message":"batch must contain at least one traffic class"}` |
| T2.6 | Port group output without PortGroupID | Same check as T1.6 | **400** | `{"code":400,"message":"port_group_id is required for port_group output"}` |
| T2.7 | PCAP output without PcapPath | Same check as T1.7 | **400** | `{"code":400,"message":"pcap_path is required for pcap output"}` |
| T2.8 | Port group not found in DB | `h.db.Where("id = ?").First` error (any) | **400** | `{"code":400,"message":"port group not found: <id>"}` |
| T2.9 | Port group has no interface configured | `iface == ""` after parsing | **400** | `{"code":400,"message":"port group has no interface configured"}` |
| T2.10 | PCAP path resolution fails (empty) | `resolvePcapPath` returns error | **400** | `{"code":400,"message":"pcap_path is required"}` (or other resolve error) |
| T2.11 | PCAP path is Windows-style (e.g. `C:\path`) | `resolvePcapPath` detects `[A-Za-z]:` pattern | **400** | `{"code":400,"message":"invalid pcap_path: Windows-style path ..."}` |
| T2.12 | PCAP path is UNC (`\\server\share`) | `resolvePcapPath` detects `\\` prefix | **400** | `{"code":400,"message":"invalid pcap_path: UNC path ..."}` |
| T2.13 | PCAP parent directory creation fails | `os.MkdirAll` fails | **400** | `{"code":400,"message":"failed to create directory ..."}` |
| T2.14 | Dual-port detected via Interface2 | `req.OutputConfig.Interface2 != ""` | **201** | Dual writer registered |
| T2.15 | Dual-port detected via replay class direction="dual" | Loop over Batch.Classes finds dual direction | **201** | Dual writer registered |
| T2.16 | Dual-port + interface mode + missing Interface2 | `dualPort && outputMode=="interface" && (req.OutputConfig==nil \|\| Interface2=="")` | **400** | `{"code":400,"message":"dual-port replay requires a second interface (interface2 in output_config)"}` |
| T2.17 | Output writer creation fails (interface) | `newInterfacePacketWriter` returns error | **500** | `{"code":500,"message":"failed to create output writer: ..."}` |
| T2.18 | Output writer creation fails (pcap) | `newPcapPacketWriter` returns error | **500** | `{"code":500,"message":"failed to create output writer: ..."}` |
| T2.19 | Second output writer creation fails (dual-port) | Dual port path, second writer creation fails, first writer is closed | **500** | `{"code":500,"message":"failed to create second output writer: ..."}` |
| T2.20 | DB create task record fails | `h.db.Create(taskModel).Error` != nil → UnregisterOutputWriter | **500** | `{"code":500,"message":"failed to create task record: ..."}` |
| T2.21 | Engine SubmitTask fails | `h.engine.SubmitTask(coreTask)` error → UnregisterOutputWriter, task marked "error" | **400** | Engine error message |
| T2.22 | Dual port with pcap output | `outputMode != "interface"`, creates `pcapFile + ".s2c"` | **201** | Dual writer with s2c suffix file |

---

### TASK3: GET /api/v1/tasks -- List Tasks (authenticated)

| # | Scenario | Logical Branch | Status | Response |
|---|----------|----------------|--------|----------|
| T3.1 | Default listing (page=1, size=20) | No query params, default values used | **200** | Paginated task list |
| T3.2 | Custom page and size | Query params parsed successfully | **200** | Custom pagination |
| T3.3 | Invalid page param | `strconv.Atoi` fails or <=0 | **200** | Defaults to 1 |
| T3.4 | Invalid size param | `strconv.Atoi` fails or <=0 | **200** | Defaults to 20 |
| T3.5 | Size exceeds 100 | `s > 100` | **200** | Capped at 100 |
| T3.6 | Status filter applied | `c.Query("status") != ""` | **200** | Filtered results |
| T3.7 | Invalid sort_by column | `!allowedSortColumns[sortBy]` | **200** | Defaults to "created_at" |
| T3.8 | Ascending sort order | `sortOrder == "ascending"` | **200** | `ORDER BY column ASC` |
| T3.9 | Descending sort order (default) | `sortOrder != "ascending"` | **200** | `ORDER BY column DESC` |
| T3.10 | No user in context | `auth.GetUserID(c)` returns "" | **401** | `{"code":401,"message":"user not authenticated"}` |
| T3.11 | DB query fails | `query.Find(&tasks).Error` != nil | **500** | `{"code":500,"message":"failed to list tasks: ..."}` |
| T3.12 | Empty result set | No tasks match query | **200** | `{"items":[],"total":0,"page":1,"size":20}` |

---

### TASK4: GET /api/v1/tasks/:id -- Get Task (authenticated)

| # | Scenario | Logical Branch | Status | Response |
|---|----------|----------------|--------|----------|
| T4.1 | Task found, includes strategy details | All checks pass | **200** | TaskResponse with Strategies populated via `convertTaskToResponseWithDB` |
| T4.2 | No user in context | `auth.GetUserID(c)` returns "" | **401** | `{"code":401,"message":"user not authenticated"}` |
| T4.3 | Missing `:id` path param | `c.Param("id")` returns "" | **400** | `{"code":400,"message":"missing task id"}` |
| T4.4 | Task not found (wrong ID or not owned) | `gorm.ErrRecordNotFound` on user-scoped query | **404** | `{"code":404,"message":"task not found"}` |
| T4.5 | DB query error | Other error | **500** | `{"code":500,"message":"failed to get task: ..."}` |
| T4.6 | Strategy DB lookup fails partially | `db.Where("id IN ?", strategyIDs).Find` error (unchecked) | **200** | Strategies array may be empty (silent degradation) |

---

### TASK5: POST /api/v1/tasks/:id/start -- Start Task (authenticated)

| # | Scenario | Logical Branch | Status | Response |
|---|----------|----------------|--------|----------|
| T5.1 | Single-strategy task, pcap output, all OK | All branches pass | **200** | `{"code":0,"message":"task started","data":{"engine_task_ids":[...]}}` |
| T5.2 | Multi-strategy task, port_group output, all OK | Multiple strategies submitted | **200** | Multiple engine_task_ids |
| T5.3 | No user in context | `auth.GetUserID(c)` returns "" | **401** | `{"code":401,"message":"user not authenticated"}` |
| T5.4 | Missing `:id` path param | `c.Param("id")` returns "" | **400** | `{"code":400,"message":"missing task id"}` |
| T5.5 | Task not found | `gorm.ErrRecordNotFound` | **404** | `{"code":404,"message":"task not found"}` |
| T5.6 | DB query error | Other error | **500** | `{"code":500,"message":"failed to get task: ..."}` |
| T5.7 | Task already running or starting | `task.Status == "running" \|\| task.Status == "starting"` | **400** | `{"code":400,"message":"task is already running"}` |
| T5.8 | Optimistic lock failure (concurrent start) | `result.RowsAffected == 0` | **400** | `{"code":400,"message":"task status changed, please retry"}` |
| T5.9 | Corrupt strategy_ids JSON | `json.Unmarshal` fails | **500** | `{"code":500,"message":"corrupt strategy_ids in task record"}` |
| T5.10 | Strategy not found (deleted before start) | `gorm.ErrRecordNotFound` during strategy validation | **400** | `{"code":400,"message":"strategy <id> not found"}` (task saved as "error") |
| T5.11 | StrategyModelToTask conversion fails | `core.StrategyModelToTask` returns error, appended to failedIDs continue loop | **400** | (falls through to further validation if others succeed, or T5.13 if none) |
| T5.12 | All strategies fail conversion | `len(coreTasks) == 0` after loop | **400** | `{"code":400,"message":"no valid strategies to execute"}` (task saved as "error") |
| T5.13 | PCAP path resolution fails | `resolvePcapPath` returns error | **400** | Error message from resolvePcapPath (task saved as "error") |
| T5.14 | PCAP path updated in DB and coreTasks | Path resolved successfully → updates both DB and all coreTasks | **200** | Updated pcap_path used throughout |
| T5.15 | Output writer creation fails (interface) | `newInterfacePacketWriter` error → appended to writerErrors | **400** if all fail, partial otherwise |
| T5.16 | Output writer creation fails (pcap) | `newPcapPacketWriter` error → appended to writerErrors | **400** if all fail, partial otherwise |
| T5.17 | All output writers fail | `len(writerErrors) > 0 && len(writerErrors) == len(coreTasks)` | **400** | `{"code":400,"message":"failed to create output writers: ..."}` (task saved as "error") |
| T5.18 | Partial writer failures | `len(writerErrors) > 0 && len(writerErrors) < len(coreTasks)` | **200** | Warning logged, failed strategies skipped, others proceed |
| T5.19 | Engine SubmitTask fails | `h.engine.SubmitTask(*ct)` error → UnregisterOutputWriter, continue | **200** or **500** (T5.21 if none submitted) |
| T5.20 | Writer error for specific task checked | `strings.HasPrefix(we, ct.ID)` -> skip=true -> continue | **200** | Skipped strategy not submitted |
| T5.21 | No engine tasks submitted | `len(submittedIDs) == 0` | **500** | `{"code":500,"message":"failed to start any strategy"}` (task saved as "error") |
| T5.22 | Port group port reservation | `task.OutputType == "port_group"` → updates port status to "using" | **200** | Ports reserved (unchecked errors) |
| T5.23 | Port group port reservation when port already used by another task | `Where("name = ? AND (status = ? OR current_task_id = ?)", iface, "idle", "")` condition | **200** | Already-used ports not reserved |
| T5.24 | Port group output config parse fails | `json.Unmarshal` error (unchecked) | **200** | Port reservation silently skipped |

---

### TASK6: POST /api/v1/tasks/:id/stop -- Stop Task (authenticated)

| # | Scenario | Logical Branch | Status | Response |
|---|----------|----------------|--------|----------|
| T6.1 | Running task stopped (single strategy) | All checks pass | **200** | `{"code":0,"message":"task stopped","data":{"stopped_engine_tasks":[...]}}` |
| T6.2 | Running task stopped (multi-strategy) | Multiple strategy loop | **200** | Multiple stopped_engine_tasks |
| T6.3 | No user in context | `auth.GetUserID(c)` returns "" | **401** | `{"code":401,"message":"user not authenticated"}` |
| T6.4 | Missing `:id` path param | `c.Param("id")` returns "" | **400** | `{"code":400,"message":"missing task id"}` |
| T6.5 | Task not found | `gorm.ErrRecordNotFound` | **404** | `{"code":404,"message":"task not found"}` |
| T6.6 | DB query error | Other error | **500** | `{"code":500,"message":"failed to get task: ..."}` |
| T6.7 | Task is not running | `task.Status != "running"` | **400** | `{"code":400,"message":"task is not running"}` |
| T6.8 | Corrupt strategy_ids JSON | `json.Unmarshal` fails → best-effort cleanup | **200** | `{"code":0,"message":"task stopped (engine cleanup may be incomplete)","data":null}` |
| T6.9 | Engine StopTask fails for one strategy | `h.engine.StopTask(engineTaskID)` error → logged, continue loop | **200** | That strategy excluded from stopped_engine_tasks |
| T6.10 | Port group ports released | `releasePortGroupPorts` called → port status set to "idle" | **200** | Ports released |
| T6.11 | Port group release: output_type not "port_group" | `task.OutputType != "port_group"` → return early | **200** | No-op |
| T6.12 | Port group release: port group not in DB | `h.db.Where("id = ?").First` error → return early | **200** | No-op (silent degradation) |
| T6.13 | Port group release: only matching ports reset | `Where("name = ? AND current_task_id = ?", iface, task.ID)` | **200** | Only ports for this task are released |

---

### TASK7: DELETE /api/v1/tasks/:id -- Delete Task (authenticated)

| # | Scenario | Logical Branch | Status | Response |
|---|----------|----------------|--------|----------|
| T7.1 | Deleted completed/stopped/failed task | All checks pass | **200** | `{"code":0,"message":"task deleted","data":null}` |
| T7.2 | No user in context | `auth.GetUserID(c)` returns "" | **401** | `{"code":401,"message":"user not authenticated"}` |
| T7.3 | Missing `:id` path param | `c.Param("id")` returns "" | **400** | `{"code":400,"message":"missing task id"}` |
| T7.4 | Task not found | `gorm.ErrRecordNotFound` | **404** | `{"code":404,"message":"task not found"}` |
| T7.5 | DB query error | Other error | **500** | `{"code":500,"message":"failed to get task: ..."}` |
| T7.6 | Task is currently running | `task.Status == "running"` | **400** | `{"code":400,"message":"cannot delete running task, stop it first"}` |
| T7.7 | DB delete fails | `h.db.Delete(&task).Error` != nil | **500** | `{"code":500,"message":"failed to delete task: ..."}` |

---

### TASK8: GET /api/v1/history -- Task History (authenticated)

| # | Scenario | Logical Branch | Status | Response |
|---|----------|----------------|--------|----------|
| T8.1 | Default history listing | No query params, defaults used | **200** | Paginated history (status IN completed,failed,stopped,error) |
| T8.2 | Custom page and size | Params parsed | **200** | Custom pagination |
| T8.3 | start_time filter valid | `strconv.ParseInt` succeeds → filter applied | **200** | Filtered by start_time |
| T8.4 | start_time filter invalid | Parse fails | **200** | Silently ignored |
| T8.5 | end_time filter valid | Parse succeeds | **200** | Filtered by end_time |
| T8.6 | end_time filter invalid | Parse fails | **200** | Silently ignored |
| T8.7 | Status filter applied | `c.Query("status") != ""` | **200** | Additional filter on query |
| T8.8 | Invalid sort_by | Defaults to "created_at" | **200** | Same as T3.7 |
| T8.9 | Ascending order | Sort order is "ascending" | **200** | Same as T3.8 |
| T8.10 | No user in context | `auth.GetUserID(c)` returns "" | **401** | `{"code":401,"message":"user not authenticated"}` |
| T8.11 | DB query fails | `query.Find(&tasks).Error` != nil | **500** | `{"code":500,"message":"failed to list history: ..."}` |
| T8.12 | No history | Empty result | **200** | `{"items":[],"total":0,...}` |

---

### TASK9: Engine Callbacks (internal)

| # | Scenario | Logical Branch | Status |
|---|----------|----------------|--------|
| T9.1 | onEngineTaskComplete: task not in DB | `h.db.Where("id = ?").First` error → log and return | No-op (log only) |
| T9.2 | onEngineTaskComplete: sub-tasks still running | Loop finds engine task in store → allDone=false | No-op (wait for more) |
| T9.3 | onEngineTaskComplete: all done + no failures | `allDone && task.Status == "running"`, no failMsgs | DB: status="completed", Progress=100 |
| T9.4 | onEngineTaskComplete: all done + some failures | failMsgs non-empty | DB: status="failed", ErrorMessage set |
| T9.5 | onEngineTaskComplete: WebSocket broadcast when no wsHub | `h.wsHub == nil` | Skips WebSocket (no-op) |
| T9.6 | onEngineTaskComplete: task status not "running" when all done | `task.Status != "running"` | No status update (race condition guard) |
| T9.7 | onEngineProgress: sub-task ID extraction | `len(parts) == 2` → parentTaskID = parts[0] | Uses parent ID |
| T9.8 | onEngineProgress: single-part engine task ID | `len(parts) != 2` → parentTaskID stays as engineID | Falls back to engine task ID |
| T9.9 | onEngineProgress: throttled (<2s since last) | `exists && now.Sub(lastUpdate) < 2*time.Second` | Returns early, no DB update |
| T9.10 | onEngineProgress: no other sub-tasks found | RangeTaskStore finds no siblings | avgProgress = progress (1 sub-task) |
| T9.11 | onEngineProgress: WebSocket broadcast | `h.wsHub != nil` | Progress broadcast to task |
| T9.12 | onEngineOutputError: short engine task ID (<=37) | `len(engineTaskID) <= 37` | taskID = engineTaskID (no truncation) |
| T9.13 | onEngineOutputError: long engine task ID (>37) | `len(engineTaskID) > 37` | taskID = first 36 chars (UUID extraction) |

---

## PORT GROUP HANDLER -- `/home/weihang/trafficGenerator/trafficgen/internal/api/rest/port_group_handler.go`

**Note:** `List` and `Get` are PUBLIC (no auth middleware). `Create` and `Delete` are under the authenticated `/api/v1` group.

### PORT1: POST /api/v1/port-groups -- Create Port Group (authenticated)

| # | Scenario | Logical Branch | Status | Response |
|---|----------|----------------|--------|----------|
| P1.1 | New port group created | All checks pass | **201** | `{"code":0,"message":"created","data":{"id":"...","name":"port_group_<hash>"}}` |
| P1.2 | Invalid JSON payload | `c.ShouldBindJSON(&req)` error | **400** | `{"code":400,"message":"invalid request: ..."}` |
| P1.3 | Empty ports array | binding `min=1` fails | **400** | (caught by P1.2) |
| P1.4 | Port with empty interface name | Loop finds `portConfig.Interface == ""` | **400** | `{"code":400,"message":"interface name is required"}` |
| P1.5 | JSON marshal of ports config fails | `json.Marshal(req.Ports)` error | **400** | `{"code":400,"message":"invalid ports config format"}` |
| P1.6 | Duplicate port group (same port config) | Existing port group found by name (hash) | **200** | `{"code":0,"message":"success","data":{"id":"...","message":"port group already exists"}}` |
| P1.7 | DB create fails | `h.db.Create(portGroup).Error` != nil | **500** | `{"code":500,"message":"failed to create port group: ..."}` |

---

### PORT2: GET /api/v1/port-groups -- List Port Groups (PUBLIC)

| # | Scenario | Logical Branch | Status | Response |
|---|----------|----------------|--------|----------|
| P2.1 | Port groups exist | DB returns results | **200** | Array of PortGroupResponse |
| P2.2 | No port groups | DB returns empty | **200** | `[]` |
| P2.3 | DB query fails | `h.db.Find(&portGroups).Error` != nil | **500** | `{"code":500,"message":"failed to list port groups: ..."}` |
| P2.4 | PortsConfig JSON deserialization fails | `json.Unmarshal` error (unchecked) | **200** | portsConfig is nil (silent degradation) |

---

### PORT3: GET /api/v1/port-groups/:id -- Get Port Group (PUBLIC)

| # | Scenario | Logical Branch | Status | Response |
|---|----------|----------------|--------|----------|
| P3.1 | Port group found | DB returns result | **200** | PortGroupResponse |
| P3.2 | Missing `:id` path param | `c.Param("id")` returns "" | **400** | `{"code":400,"message":"missing port group id"}` |
| P3.3 | Port group not found | `gorm.ErrRecordNotFound` | **404** | `{"code":404,"message":"port group not found"}` |
| P3.4 | DB query error | Other error | **500** | `{"code":500,"message":"failed to get port group: ..."}` |

---

### PORT4: DELETE /api/v1/port-groups/:id -- Delete Port Group (authenticated)

| # | Scenario | Logical Branch | Status | Response |
|---|----------|----------------|--------|----------|
| P4.1 | Port group deleted | Not referenced by tasks, db.Delete succeeds | **200** | `{"code":0,"message":"port group deleted","data":null}` |
| P4.2 | Missing `:id` path param | `c.Param("id")` returns "" | **400** | `{"code":400,"message":"missing port group id"}` |
| P4.3 | Port group not found | `gorm.ErrRecordNotFound` | **404** | `{"code":404,"message":"port group not found"}` |
| P4.4 | DB query error | Other error | **500** | `{"code":500,"message":"failed to get port group: ..."}` |
| P4.5 | Port group referenced by tasks | `taskCount > 0` (LIKE search on output_config) | **400** | `{"code":400,"message":"port group is used by tasks, cannot delete"}` |
| P4.6 | DB delete fails | `h.db.Delete(&portGroup).Error` != nil | **500** | `{"code":500,"message":"failed to delete port group: ..."}` |

---

## SYSTEM HANDLER -- `/home/weihang/trafficGenerator/trafficgen/internal/api/rest/system.go`

### SYS1: GET /api/v1/system/status -- System Status (authenticated)

| # | Scenario | Logical Branch | Status | Response |
|---|----------|----------------|--------|----------|
| Y1.1 | Engine running, DB connected | `h.db != nil` + `CountActiveTasks` succeeds | **200** | SystemStatusResponse with real activeTasks |
| Y1.2 | Engine running, DB not set | `h.db == nil` | **200** | activeTasks = 0 |
| Y1.3 | Engine running, DB query fails | `h.db.CountActiveTasks()` returns error | **200** | activeTasks = 0 (silent degradation) |
| Y1.4 | Engine stopped | `h.engine.IsRunning()` returns false | **200** | running=false |

---

### SYS2: GET /api/v1/system/protocols -- Get Protocols (authenticated)

| # | Scenario | Logical Branch | Status | Response |
|---|----------|----------------|--------|----------|
| Y2.1 | Always returns | Static list (no branches) | **200** | `["tcp","udp","http","dns","icmp","arp"]` |

---

### SYS3: GET /api/v1/system/stats -- Get Stats (authenticated)

| # | Scenario | Logical Branch | Status | Response |
|---|----------|----------------|--------|----------|
| Y3.1 | Engine returns task stats | All type assertions succeed | **200** | Aggregated stats across running tasks |
| Y3.2 | Engine stats has no "tasks" key | Type assertion `ok == false` | **200** | totalPackets=0, totalBytes=0, etc. |
| Y3.3 | Single task stats missing "stats" field | Nested type assertion fails | **200** | That task's stats skipped |
| Y3.4 | Stats field type mismatch (int64 assertion) | `stats["packets_sent"].(int64)` fails | **200** | That stat skipped (silent degradation) |
| Y3.5 | Stats field type mismatch (float64 assertion) | `stats["current_pps"].(float64)` fails | **200** | That stat skipped (silent degradation) |
| Y3.6 | Task "protocol" field missing or wrong type | `task["protocol"].(string)` fails | **200** | Protocol not counted |
| Y3.7 | DB not set (nil) | `h.db == nil` | **200** | Only engine task protocols counted |
| Y3.8 | DB CountTasksByProtocol succeeds | Merges with engine protocol counts | **200** | Combined protocol distribution |
| Y3.9 | DB CountTasksByProtocol fails | `h.db.CountTasksByProtocol()` error | **200** | DB protocol counts skipped (silent degradation) |

---

### SYS4: GET /health -- Health Check (PUBLIC)

| # | Scenario | Status | Response |
|---|----------|--------|----------|
| H1.1 | Always returns | **200** | `{"status":"healthy"}` |

---

### SYS5: GET /ready -- Readiness Check (PUBLIC)

| # | Scenario | Logical Branch | Status | Response |
|---|----------|----------------|--------|----------|
| H2.1 | Engine is running | `h.engine.IsRunning()` returns true | **200** | `{"status":"ready","database":"connected","redis":"connected"}` |
| H2.2 | Engine is not running | `!h.engine.IsRunning()` | **503** | `{"status":"not ready","reason":"engine not running"}` |

---

## SERVER SETUP -- `/home/weihang/trafficGenerator/trafficgen/internal/api/rest/server.go`

### SERVER-ROUTE Registration Summary

| # | Endpoint | Auth Required | Handler |
|---|----------|---------------|---------|
| R1 | GET /health | No | `systemHandler.HealthCheck` |
| R2 | GET /ready | No | `systemHandler.ReadyCheck` |
| R3 | GET /ws | No (if wsHandler set) | `s.wsHandler.Handle` |
| R4 | GET <metrics.Path> | No (if enabled) | Prometheus handler |
| R5 | POST /api/v1/auth/register | No | `authHandler.Register` |
| R6 | POST /api/v1/auth/login | No | `authHandler.Login` |
| R7 | GET /api/v1/auth/validate | No | `authHandler.ValidateToken` |
| R8 | POST /api/v1/auth/logout | No | `authHandler.Logout` |
| R9 | GET /api/v1/ports | No | `s.listPorts` |
| R10 | GET /api/v1/port-groups | No | `portGroupHandler.List` |
| R11 | GET /api/v1/port-groups/:id | No | `portGroupHandler.Get` |
| R12-Rxx | All /api/v1/* | Yes (AuthMiddlewareWithDB) | Various handlers |
| Rlast | SPA fallback (NoRoute) | No | Serves index.html |

### Server Setup Branches

| # | Scenario | Logical Branch | Effect |
|---|----------|----------------|--------|
| SR1 | Config mode = "release" | `s.config.Server.Mode == "release"` | gin.ReleaseMode |
| SR2 | Config mode = "test" | `s.config.Server.Mode == "test"` | gin.TestMode |
| SR3 | Config mode = anything else (or empty) | default case | gin.DebugMode |
| SR4 | WebSocket handler provided | `s.wsHandler != nil` | WS endpoint registered, JWT manager injected |
| SR5 | WebSocket handler nil | `s.wsHandler == nil` | No WS endpoint |
| SR6 | Metrics enabled | `s.config.Metrics.Enabled == true` | Prometheus endpoint registered |
| SR7 | Metrics disabled | `s.config.Metrics.Enabled == false` | No metrics endpoint |

### CORS Middleware Branches

| # | Scenario | Logical Branch | Effect |
|---|----------|----------------|--------|
| C1 | Origin empty (not from browser) | `origin == ""` | `allowed` stays false, but `!allowed && origin != ""` is false → goes to `c.Next()` |
| C2 | Origin matches allowed list | `o == origin` or `o == "*"` | CORS headers set, `allowed=true` |
| C3 | Origin not in allowed list | Loop exhausts without match, `allowed` stays false | Denied: `!allowed && origin != ""` → just `c.Next()`, no CORS headers |
| C4 | Preflight (OPTIONS) request | `c.Request.Method == "OPTIONS"` | `c.AbortWithStatus(204)` |

### Interface Handler Branches

| # | Scenario | Logical Branch | Status |
|---|----------|----------------|--------|
| I1 | ifaceMgr is nil | `s.ifaceMgr == nil` | 200 with empty list |
| I2 | portSched is nil | `s.portSched == nil` | inUseMap stays empty |
| I3 | Interface discovery fails | `s.ifaceMgr.Refresh()` error | 500 |
| I4 | Interface discovery succeeds | All OK | 200 |

### listPorts Branches

| # | Scenario | Logical Branch | Status |
|---|----------|----------------|--------|
| LP1 | Ports exist | DB returns results | 200 |
| LP2 | DB query fails | `s.db.Find(&ports).Error` != nil | 500 |

---

## Summary of All Endpoints

| Tag | Method | Path | Auth | Total Branch Points |
|-----|--------|------|------|-------------------|
| AUTH1 | POST | /api/v1/auth/register | No | 6 |
| AUTH2 | POST | /api/v1/auth/login | No | 8 |
| AUTH3 | GET | /api/v1/auth/validate | No | 7 |
| AUTH4 | POST | /api/v1/auth/logout | No | 5 |
| AUTH5 | POST | /api/v1/auth/refresh | Yes | 5 |
| AUTH6 | GET | /api/v1/user/profile | Yes | 3 |
| AUTH7 | PUT | /api/v1/user/profile | Yes | 12 |
| AUTH8 | DELETE | /api/v1/user/profile | Yes | 5 |
| STRAT1 | POST | /api/v1/strategies | Yes | 17 |
| STRAT2 | GET | /api/v1/strategies | Yes | 5 |
| STRAT3 | GET | /api/v1/strategies/:id | Yes | 4 |
| STRAT4 | PUT | /api/v1/strategies/:id | Yes | 15 |
| STRAT5 | DELETE | /api/v1/strategies/:id | Yes | 7 |
| STRAT6 | GET | /api/v1/strategies/:id/tasks | Yes | 5 |
| TASK1 | POST | /api/v1/tasks | Yes | 11 |
| TASK2 | POST | /api/v1/tasks/batch | Yes | 22 |
| TASK3 | GET | /api/v1/tasks | Yes | 11 |
| TASK4 | GET | /api/v1/tasks/:id | Yes | 5 |
| TASK5 | POST | /api/v1/tasks/:id/start | Yes | 24 |
| TASK6 | POST | /api/v1/tasks/:id/stop | Yes | 13 |
| TASK7 | DELETE | /api/v1/tasks/:id | Yes | 6 |
| TASK8 | GET | /api/v1/history | Yes | 12 |
| TASK9 | (callbacks) | Engine callbacks (internal) | - | 13 |
| PORT1 | POST | /api/v1/port-groups | Yes | 6 |
| PORT2 | GET | /api/v1/port-groups | No | 3 |
| PORT3 | GET | /api/v1/port-groups/:id | No | 3 |
| PORT4 | DELETE | /api/v1/port-groups/:id | Yes | 6 |
| SYS1 | GET | /api/v1/system/status | Yes | 3 |
| SYS2 | GET | /api/v1/system/protocols | Yes | 1 |
| SYS3 | GET | /api/v1/system/stats | Yes | 9 |
| SYS4 | GET | /health | No | 1 |
| SYS5 | GET | /ready | No | 2 |
| - | (middleware) | AuthMiddlewareWithDB | M1-M8 | 8 |
| - | (setup) | Server setup | SR1-SR7 + C1-C4 + I1-I4 + LP1-LP2 | 15 |

**Total unique business scenarios enumerated: ~260** (including middleware, setup, and engine callbacks)
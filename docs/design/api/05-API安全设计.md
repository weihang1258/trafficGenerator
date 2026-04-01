# API设计 - 安全设计

**文档版本**: v1.0  
**更新日期**: 2026-04-01  
**模块**: internal/api

---

## 1. 认证机制

### 1.1 JWT认证

```go
type JWTClaims struct {
    UserID   string   `json:"user_id"`
    Username string   `json:"username"`
    Roles    []string `json:"roles"`
    jwt.RegisteredClaims
}

func GenerateToken(userID, username string, roles []string) (string, error) {
    claims := JWTClaims{
        UserID:   userID,
        Username: username,
        Roles:    roles,
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
            IssuedAt:  jwt.NewNumericDate(time.Now()),
            Issuer:    "traffic-generator",
        },
    }
    
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString([]byte(os.Getenv("JWT_SECRET")))
}
```

### 1.2 认证中间件

```go
func AuthMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        authHeader := c.GetHeader("Authorization")
        if authHeader == "" {
            c.JSON(401, gin.H{"error": "missing authorization header"})
            c.Abort()
            return
        }
        
        tokenString := strings.TrimPrefix(authHeader, "Bearer ")
        claims := &JWTClaims{}
        
        token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
            return []byte(os.Getenv("JWT_SECRET")), nil
        })
        
        if err != nil || !token.Valid {
            c.JSON(401, gin.H{"error": "invalid token"})
            c.Abort()
            return
        }
        
        c.Set("user_id", claims.UserID)
        c.Set("roles", claims.Roles)
        c.Next()
    }
}
```

---

## 2. 权限控制 (RBAC)

### 2.1 角色定义

```go
const (
    RoleAdmin    = "admin"    // 全部权限
    RoleOperator = "operator" // 操作权限
    RoleViewer   = "viewer"   // 只读权限
)

var rolePermissions = map[string][]string{
    RoleAdmin:    {"*"},
    RoleOperator: {"task:create", "task:start", "task:stop", "task:read"},
    RoleViewer:   {"task:read", "strategy:read", "metrics:read"},
}
```

### 2.2 权限中间件

```go
func RequirePermission(permission string) gin.HandlerFunc {
    return func(c *gin.Context) {
        roles, _ := c.Get("roles")
        userRoles := roles.([]string)
        
        if !hasPermission(userRoles, permission) {
            c.JSON(403, gin.H{"error": "insufficient permissions"})
            c.Abort()
            return
        }
        c.Next()
    }
}

// 使用示例
router.POST("/tasks", AuthMiddleware(), RequirePermission("task:create"), createTask)
```

---

## 3. API限流

### 3.1 令牌桶限流

```go
import "golang.org/x/time/rate"

var limiters = make(map[string]*rate.Limiter)
var mu sync.Mutex

func getRateLimiter(userID string) *rate.Limiter {
    mu.Lock()
    defer mu.Unlock()
    
    limiter, exists := limiters[userID]
    if !exists {
        limiter = rate.NewLimiter(rate.Limit(100), 200) // 100 req/s, burst 200
        limiters[userID] = limiter
    }
    return limiter
}

func RateLimitMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        userID, _ := c.Get("user_id")
        limiter := getRateLimiter(userID.(string))
        
        if !limiter.Allow() {
            c.Header("X-RateLimit-Limit", "100")
            c.Header("X-RateLimit-Remaining", "0")
            c.Header("X-RateLimit-Reset", fmt.Sprintf("%d", time.Now().Add(time.Second).Unix()))
            c.JSON(429, gin.H{"error": "rate limit exceeded"})
            c.Abort()
            return
        }
        c.Next()
    }
}
```

---

## 4. 输入验证

### 4.1 参数验证

```go
type CreateTaskRequest struct {
    Name        string   `json:"name" binding:"required,min=1,max=255"`
    Description string   `json:"description" binding:"max=1000"`
    Protocol    string   `json:"protocol" binding:"required,oneof=tcp udp http dns"`
    Spec        TaskSpec `json:"spec" binding:"required"`
}

func createTask(c *gin.Context) {
    var req CreateTaskRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }
    
    // 业务逻辑
}
```

### 4.2 SQL注入防护

```go
// 使用参数化查询
func GetTask(db *sql.DB, taskID string) (*Task, error) {
    query := "SELECT * FROM tasks WHERE id = ?"
    row := db.QueryRow(query, taskID)
    
    var task Task
    err := row.Scan(&task.ID, &task.Name, &task.Status)
    return &task, err
}
```

---

## 5. 数据加密

### 5.1 敏感数据加密

```go
import "crypto/aes"
import "crypto/cipher"

func encryptSensitiveData(plaintext string, key []byte) (string, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }
    
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }
    
    nonce := make([]byte, gcm.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return "", err
    }
    
    ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
    return base64.StdEncoding.EncodeToString(ciphertext), nil
}
```

---

## 6. HTTPS配置

```go
func StartHTTPSServer() {
    router := gin.Default()
    
    // TLS配置
    tlsConfig := &tls.Config{
        MinVersion: tls.VersionTLS12,
        CipherSuites: []uint16{
            tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        },
    }
    
    server := &http.Server{
        Addr:      ":8443",
        Handler:   router,
        TLSConfig: tlsConfig,
    }
    
    server.ListenAndServeTLS("cert.pem", "key.pem")
}
```

---

## 7. 安全响应头

```go
func SecurityHeadersMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        c.Header("X-Content-Type-Options", "nosniff")
        c.Header("X-Frame-Options", "DENY")
        c.Header("X-XSS-Protection", "1; mode=block")
        c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        c.Header("Content-Security-Policy", "default-src 'self'")
        c.Next()
    }
}
```

---

## 8. 审计日志

```go
func AuditLogMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        start := time.Now()
        
        c.Next()
        
        userID, _ := c.Get("user_id")
        log.Info("api audit",
            zap.String("user_id", userID.(string)),
            zap.String("method", c.Request.Method),
            zap.String("path", c.Request.URL.Path),
            zap.Int("status", c.Writer.Status()),
            zap.Duration("latency", time.Since(start)))
    }
}
```

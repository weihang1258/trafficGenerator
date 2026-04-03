# Traffic Generator 部署指南

## 部署场景说明

### 场景对比

| 场景 | 前端位置 | 后端位置 | 是否需要 Nginx | 跨域问题 | 适用环境 |
|------|---------|---------|---------------|---------|---------|
| **场景1: 后端服务静态文件** | Go服务器 | Go服务器 | ❌ 不需要 | ✅ 无 | 开发/小型部署 |
| **场景2: Nginx反向代理** | Nginx | Go服务器 | ✅ 需要 | ✅ 无 | 生产环境（推荐） |
| **场景3: 前后端分离** | 独立服务器 | 独立服务器 | ⚠️ 可选 | ⚠️ 需配置CORS | 大型系统 |

---

## 场景 1: 后端直接服务前端（当前方式）

### 架构图

```
用户 → http://server-ip:8080 → Go后端
                                  ├─ 静态文件 (/)
                                  └─ API (/api/v1/*)
```

### 部署步骤

#### 1. 构建前端

```bash
cd trafficgen/web
npm install
npm run build
# 生成 dist/ 目录
```

#### 2. 配置后端服务静态文件

修改 `cmd/server/main.go` 或在 Gin 路由中添加：

```go
// 服务前端静态文件
router.Static("/assets", "./web/dist/assets")
router.StaticFile("/", "./web/dist/index.html")
router.NoRoute(func(c *gin.Context) {
    c.File("./web/dist/index.html")
})
```

#### 3. 启动服务

```bash
cd trafficgen
./bin/trafficgen -config configs/config.yaml
```

#### 4. 访问

- 本机: `http://localhost:8080`
- 局域网: `http://192.168.1.100:8080`
- 公网: `http://your-server-ip:8080`

### 优点
- ✅ 部署简单，单个服务
- ✅ 无跨域问题
- ✅ 适合小型部署

### 缺点
- ❌ Go 服务器负责静态文件服务（性能不如 Nginx）
- ❌ 无法独立扩展前后端
- ❌ 无法使用 CDN 加速前端

---

## 场景 2: Nginx 反向代理（生产环境推荐）⭐

### 架构图

```
用户 → http://your-domain.com (Nginx:80)
           ├─ / → 前端静态文件
           ├─ /api/* → 反向代理到 :8080
           └─ /ws → WebSocket 代理到 :8080
```

### 部署步骤

#### 1. 构建前端

```bash
cd trafficgen/web
npm run build
```

#### 2. 部署前端到 Nginx

```bash
# 复制前端文件到 Nginx 目录
sudo mkdir -p /var/www/trafficgen/web
sudo cp -r dist/* /var/www/trafficgen/web/
```

#### 3. 配置 Nginx

```bash
# 复制配置文件
sudo cp deployments/nginx/trafficgen.conf /etc/nginx/sites-available/
sudo ln -s /etc/nginx/sites-available/trafficgen.conf /etc/nginx/sites-enabled/

# 修改配置文件中的域名
sudo nano /etc/nginx/sites-available/trafficgen.conf
# 修改: server_name your-domain.com;

# 测试配置
sudo nginx -t

# 重载 Nginx
sudo systemctl reload nginx
```

#### 4. 启动后端服务

```bash
cd trafficgen
./bin/trafficgen -config configs/config.yaml
```

#### 5. 访问

- `http://your-domain.com`
- `http://your-server-ip`

### 优点
- ✅ Nginx 高效服务静态文件
- ✅ 支持 HTTPS/SSL
- ✅ 支持负载均衡
- ✅ 支持 Gzip 压缩
- ✅ 无跨域问题
- ✅ 生产环境标准方案

### 缺点
- ⚠️ 需要配置 Nginx

---

## 场景 3: 前后端完全分离

### 架构图

```
用户 → http://frontend.com (前端服务器)
         ↓ API 请求
       http://api.backend.com (后端服务器)
```

### 部署步骤

#### 1. 配置环境变量

创建 `.env.production.local`:

```bash
# 指向后端 API 地址
VITE_API_BASE_URL=http://api.backend.com/api/v1
```

#### 2. 构建前端

```bash
cd trafficgen/web
npm run build
```

#### 3. 部署前端（任意静态文件服务器）

```bash
# 方式1: Nginx
sudo cp -r dist/* /var/www/frontend/

# 方式2: Apache
sudo cp -r dist/* /var/www/html/

# 方式3: CDN
# 上传 dist/ 到 CDN
```

#### 4. 配置后端 CORS

修改 `internal/api/rest/server.go`:

```go
func CORSMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        c.Writer.Header().Set("Access-Control-Allow-Origin", "http://frontend.com")
        c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
        c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
        c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        
        if c.Request.Method == "OPTIONS" {
            c.AbortWithStatus(204)
            return
        }
        c.Next()
    }
}
```

#### 5. 启动后端

```bash
cd trafficgen
./bin/trafficgen -config configs/config.yaml
```

### 优点
- ✅ 前后端完全独立
- ✅ 可以独立扩展
- ✅ 前端可以使用 CDN

### 缺点
- ⚠️ 需要配置 CORS
- ⚠️ 跨域请求有性能损耗
- ⚠️ 配置复杂

---

## Docker 部署

### Docker Compose 配置

```yaml
version: '3.8'

services:
  # 后端服务
  trafficgen:
    build: .
    ports:
      - "8080:8080"
    volumes:
      - ./configs:/app/configs
      - ./data:/app/data
    environment:
      - GIN_MODE=release
    restart: unless-stopped

  # Nginx 反向代理
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./web/dist:/usr/share/nginx/html
      - ./deployments/nginx/trafficgen.conf:/etc/nginx/conf.d/default.conf
    depends_on:
      - trafficgen
    restart: unless-stopped
```

### 部署命令

```bash
# 构建并启动
docker-compose up -d --build

# 查看日志
docker-compose logs -f

# 停止服务
docker-compose down
```

---

## 环境变量说明

### 前端环境变量

| 变量名 | 说明 | 开发环境 | 生产环境 |
|--------|------|---------|---------|
| `VITE_API_BASE_URL` | API 基础地址 | `http://localhost:8080/api/v1` | `/api/v1` |

### 后端环境变量

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `SERVER_HOST` | 服务器监听地址 | `0.0.0.0` |
| `SERVER_PORT` | 服务器端口 | `8080` |
| `GIN_MODE` | Gin 运行模式 | `debug` |

---

## 常见问题

### Q1: 非本机访问显示 404？

**原因**: 前端路由使用 History 模式，刷新页面时服务器找不到对应文件。

**解决**:
- Nginx: 配置 `try_files $uri $uri/ /index.html;`
- Go: 配置 NoRoute 返回 index.html

### Q2: API 请求失败，显示跨域错误？

**原因**: 前后端不在同一域名下，浏览器阻止跨域请求。

**解决**:
- 方案1: 使用 Nginx 反向代理（推荐）
- 方案2: 配置后端 CORS

### Q3: WebSocket 连接失败？

**原因**: Nginx 未正确配置 WebSocket 代理。

**解决**: 添加以下配置
```nginx
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection "upgrade";
```

### Q4: 静态资源加载慢？

**解决**:
- 启用 Nginx Gzip 压缩
- 配置静态资源缓存
- 使用 CDN

---

## 推荐部署方案

### 开发环境
- 使用 **场景1**（后端服务静态文件）
- 简单快速，适合开发调试

### 生产环境
- 使用 **场景2**（Nginx 反向代理）⭐
- 性能好，配置标准，易于维护

### 大型系统
- 使用 **场景3**（前后端分离）
- 配合 CDN、负载均衡、容器编排

---

## 总结

**你的问题答案**：

> 如果前端到后端没有中间层处理，那在非本机访问时候，是否就不通了？

**答案**: ✅ **不会不通**，但取决于部署方式：

1. **当前方式（后端服务静态文件）**:
   - ✅ 本机访问: `http://localhost:8080` - 正常
   - ✅ 局域网访问: `http://192.168.1.100:8080` - 正常
   - ✅ 公网访问: `http://your-server-ip:8080` - 正常
   - **原因**: 前后端在同一服务器，使用相对路径 `/api/v1`

2. **如果前后端分离部署**:
   - ❌ 会出现问题（跨域）
   - ✅ 需要配置 CORS 或使用 Nginx 反向代理

**建议**: 
- 当前保持现有方式即可正常访问
- 生产环境建议使用 Nginx 反向代理

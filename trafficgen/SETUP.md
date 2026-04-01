# 开发环境设置指南

## 1. 安装Go 1.21+

### Windows
```powershell
# 方法1: 使用winget
winget install GoLang.Go

# 方法2: 使用Chocolatey
choco install golang

# 方法3: 手动下载
# 下载地址: https://go.dev/dl/
# 下载 go1.21.x.windows-amd64.msi 并安装
```

### Linux
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install golang-go

# 或使用官方安装包
wget https://go.dev/dl/go1.21.6.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.6.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
```

### macOS
```bash
# 使用Homebrew
brew install go

# 或使用官方安装包
# 下载 go1.21.6.darwin-amd64.pkg 并安装
```

## 2. 验证安装

```bash
go version
# 输出: go version go1.21.x windows/amd64
```

## 3. 安装项目依赖

```bash
cd trafficgen
go mod tidy
```

## 4. 编译项目

```bash
# 编译
go build -o bin/trafficgen.exe ./cmd/server

# 或使用Makefile
make build
```

## 5. 运行测试

```bash
go test ./... -v
```

## 6. 运行服务

```bash
./bin/trafficgen.exe -config configs/config.yaml
```

## 7. 访问服务

- API: http://localhost:8080/api/v1
- 健康检查: http://localhost:8080/health
- 监控指标: http://localhost:8080/metrics

## 前端开发环境

### 安装Node.js

```bash
# Windows (winget)
winget install OpenJS.NodeJS.LTS

# 或从 https://nodejs.org/ 下载安装
```

### 安装依赖并运行

```bash
cd trafficgen/web
npm install
npm run dev
```

## Docker开发环境

如果没有安装Go，可以使用Docker:

```bash
cd trafficgen

# 构建镜像
docker build -t trafficgen:latest .

# 运行容器
docker run -p 8080:8080 trafficgen:latest
```

## 依赖说明

### 后端主要依赖
- github.com/gin-gonic/gin - Web框架
- github.com/google/gopacket - 报文处理
- gorm.io/gorm - ORM
- go.uber.org/zap - 日志
- github.com/prometheus/client_golang - 监控指标
- github.com/gorilla/websocket - WebSocket
- github.com/golang-jwt/jwt/v5 - JWT认证

### 前端主要依赖
- vue - Vue 3框架
- element-plus - UI组件库
- echarts - 图表库
- axios - HTTP客户端
- pinia - 状态管理

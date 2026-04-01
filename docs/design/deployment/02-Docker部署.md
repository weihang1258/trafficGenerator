# 部署方案 - Docker部署

**文档版本**: v1.0  
**更新日期**: 2026-04-01

---

## 1. Dockerfile

```dockerfile
# 构建阶段
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY . .
RUN go mod download
RUN go build -o traffic-generator cmd/server/main.go

# 运行阶段
FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/traffic-generator .
COPY --from=builder /app/configs ./configs
EXPOSE 8080 9090
CMD ["./traffic-generator", "server"]
```

---

## 2. docker-compose.yml

```yaml
version: '3.8'

services:
  traffic-generator:
    build: .
    ports:
      - "8080:8080"
      - "9090:9090"
    environment:
      - DB_HOST=postgres
      - REDIS_HOST=redis
    volumes:
      - ./configs:/root/configs
    depends_on:
      - postgres
      - redis
  
  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: traffic_generator
      POSTGRES_USER: admin
      POSTGRES_PASSWORD: password
    volumes:
      - postgres_data:/var/lib/postgresql/data
  
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

volumes:
  postgres_data:
```

---

## 3. 构建和运行

```bash
# 构建镜像
docker build -t traffic-generator:v2.0.0 .

# 运行容器
docker run -d \
  -p 8080:8080 \
  -p 9090:9090 \
  -v $(pwd)/configs:/root/configs \
  traffic-generator:v2.0.0

# 使用docker-compose
docker-compose up -d
```


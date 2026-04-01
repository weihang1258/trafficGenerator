# CI/CD流程

**文档版本**: v1.0  
**更新日期**: 2026-04-01

---

## 1. GitHub Actions配置

```yaml
# .github/workflows/ci.yml
name: CI

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.21'
      
      - name: Cache dependencies
        uses: actions/cache@v3
        with:
          path: ~/go/pkg/mod
          key: ${{ runner.os }}-go-${{ hashFiles('**/go.sum') }}
      
      - name: Install dependencies
        run: go mod download
      
      - name: Run tests
        run: go test -v -race -coverprofile=coverage.out ./...
      
      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          file: ./coverage.out
  
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: golangci/golangci-lint-action@v3
        with:
          version: latest
  
  build:
    needs: [test, lint]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Build binary
        run: |
          go build -o traffic-generator cmd/server/main.go
      
      - name: Build Docker image
        run: |
          docker build -t traffic-generator:${{ github.sha }} .
```

---

## 2. 部署流程

```yaml
# .github/workflows/deploy.yml
name: Deploy

on:
  push:
    tags:
      - 'v*'

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Build and push Docker
        run: |
          echo ${{ secrets.DOCKER_PASSWORD }} | docker login -u ${{ secrets.DOCKER_USERNAME }} --password-stdin
          docker build -t yourorg/traffic-generator:${{ github.ref_name }} .
          docker push yourorg/traffic-generator:${{ github.ref_name }}
      
      - name: Deploy to K8s
        run: |
          kubectl set image deployment/traffic-generator \
            traffic-generator=yourorg/traffic-generator:${{ github.ref_name }}
```

---

## 3. Makefile

```makefile
.PHONY: all build test clean

all: test build

build:
	go build -o bin/traffic-generator cmd/server/main.go

test:
	go test -v -race ./...

lint:
	golangci-lint run

docker-build:
	docker build -t traffic-generator:latest .

deploy:
	kubectl apply -f k8s/
```

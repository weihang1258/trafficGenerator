.PHONY: all build run test clean lint build-fs build-all

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

# Binary names
BINARY_NAME=trafficgen
BINARY_UNIX=$(BINARY_NAME)_unix
FS_BINARY_NAME=tgserver-fs

# Main packages
MAIN_PACKAGE=./cmd/server
FS_MAIN_PACKAGE=./cmd/fs

# Build directory
BUILD_DIR=./bin

all: clean deps build

deps:
	$(GOMOD) download
	$(GOMOD) tidy

build:
	mkdir -p $(BUILD_DIR)
	$(GOBUILD) -buildvcs=false -o $(BUILD_DIR)/$(BINARY_NAME) $(MAIN_PACKAGE)

# build-fs builds the standalone filesystem CLI binary tgserver-fs.
build-fs:
	mkdir -p $(BUILD_DIR)
	$(GOBUILD) -buildvcs=false -o $(BUILD_DIR)/$(FS_BINARY_NAME) $(FS_MAIN_PACKAGE)

# build-all builds both the main server binary and the filesystem CLI binary.
build-all: build build-fs

run:
	$(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME) $(MAIN_PACKAGE)
	$(BUILD_DIR)/$(BINARY_NAME)

test:
	$(GOTEST) -v -race -coverprofile=coverage.out ./...

test-coverage: test
	$(GOCMD) tool cover -html=coverage.out -o coverage.html

clean:
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html

lint:
	golangci-lint run

fmt:
	$(GOCMD) fmt ./...

vet:
	$(GOCMD) vet ./...

# Cross compilation
build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_UNIX) $(MAIN_PACKAGE)

build-windows:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME).exe $(MAIN_PACKAGE)

build-darwin:
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME)_darwin $(MAIN_PACKAGE)

# Docker
docker-build:
	docker build -t trafficgen:latest .

docker-run:
	docker run -p 8080:8080 trafficgen:latest

# Development
dev:
	$(GOCMD) run $(MAIN_PACKAGE)/main.go

# Install
install:
	$(GOCMD) install $(MAIN_PACKAGE)

# ---- Release packaging (v1: Linux amd64, MCP service) ----------------------
# CGO_ENABLED=1 必须：pcap 注入/解析走 cgo+libpcap（构建机需 libpcap-dev）。
# 交叉编译目标（build-linux/windows/darwin, CGO_ENABLED=0）与 pcap 面不兼容，
# 发布一律走 dist。
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
DIST_DIR = dist
PKG_NAME = trafficgen-$(VERSION)-linux-amd64
RELEASE_LDFLAGS = -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

.PHONY: build-release dist clean-dist

build-release:
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=1 $(GOBUILD) -buildvcs=false -ldflags "$(RELEASE_LDFLAGS)" -o $(BUILD_DIR)/trafficgen ./cmd/server
	@$(BUILD_DIR)/trafficgen -version

dist: build-release
	rm -rf $(DIST_DIR)/$(PKG_NAME)
	mkdir -p $(DIST_DIR)/$(PKG_NAME)
	cp $(BUILD_DIR)/trafficgen $(DIST_DIR)/$(PKG_NAME)/
	cp deploy/config.yaml.example deploy/uninstall.sh deploy/README.md $(DIST_DIR)/$(PKG_NAME)/
	# install.sh 烧入发布版本号：curl | sudo bash 零参数在线安装（可被
	# TRAFFICGEN_RELEASE_BASE / 显式参数覆盖）。源码副本保留占位符。
	sed "s/__RELEASE_VERSION__/$(VERSION)/" deploy/install.sh > $(DIST_DIR)/$(PKG_NAME)/install.sh
	chmod 0755 $(DIST_DIR)/$(PKG_NAME)/trafficgen $(DIST_DIR)/$(PKG_NAME)/install.sh $(DIST_DIR)/$(PKG_NAME)/uninstall.sh
	tar -czf $(DIST_DIR)/$(PKG_NAME).tar.gz -C $(DIST_DIR) $(PKG_NAME)
	cd $(DIST_DIR) && sha256sum $(PKG_NAME).tar.gz > SHA256SUMS
	cp $(DIST_DIR)/$(PKG_NAME)/install.sh $(DIST_DIR)/install.sh
	@echo "=== dist: $(DIST_DIR)/$(PKG_NAME).tar.gz (+ SHA256SUMS + install.sh) ==="

# serve-dist 起一个临时 HTTP 服务器托管发布产物（在线安装的服务端调试）：
#   curl -fsSL http://<本机IP>:9000/install.sh | sudo bash
serve-dist:
	cd $(DIST_DIR) && python3 -m http.server 9000

clean-dist:
	rm -rf $(DIST_DIR)

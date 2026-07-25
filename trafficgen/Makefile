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

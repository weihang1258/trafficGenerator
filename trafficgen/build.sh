#!/bin/bash
# Linux/macOS编译验证脚本

echo "========================================"
echo "Traffic Generator - Build Verification"
echo "========================================"
echo

# Check Go installation
if ! command -v go &> /dev/null; then
    echo "[ERROR] Go is not installed!"
    echo "Please install Go 1.21+ from https://go.dev/dl/"
    echo "Or use: brew install go (macOS) / apt install golang-go (Ubuntu)"
    exit 1
fi

echo "[OK] Go is installed"
go version
echo

# Navigate to project directory
cd "$(dirname "$0")"

# Download dependencies
echo "[STEP] Downloading dependencies..."
go mod tidy
if [ $? -ne 0 ]; then
    echo "[ERROR] Failed to download dependencies"
    exit 1
fi
echo "[OK] Dependencies downloaded"
echo

# Build project
echo "[STEP] Building project..."
mkdir -p bin
go build -o bin/trafficgen ./cmd/server
if [ $? -ne 0 ]; then
    echo "[ERROR] Build failed"
    exit 1
fi
echo "[OK] Build successful: bin/trafficgen"
echo

# Run tests
echo "[STEP] Running tests..."
go test ./... -v
if [ $? -ne 0 ]; then
    echo "[WARNING] Some tests failed"
else
    echo "[OK] All tests passed"
fi
echo

echo "========================================"
echo "Build verification complete!"
echo "========================================"
echo
echo "To run the server:"
echo "  ./bin/trafficgen -config configs/config.yaml"
echo

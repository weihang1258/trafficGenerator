@echo off
REM Windows编译验证脚本

echo ========================================
echo Traffic Generator - Build Verification
echo ========================================
echo.

REM Check Go installation
where go >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Go is not installed!
    echo Please install Go 1.21+ from https://go.dev/dl/
    echo Or use: winget install GoLang.Go
    exit /b 1
)

echo [OK] Go is installed
go version
echo.

REM Navigate to project directory
cd /d "%~dp0"

REM Download dependencies
echo [STEP] Downloading dependencies...
go mod tidy
if %errorlevel% neq 0 (
    echo [ERROR] Failed to download dependencies
    exit /b 1
)
echo [OK] Dependencies downloaded
echo.

REM Build project
echo [STEP] Building project...
if not exist bin mkdir bin
go build -o bin\trafficgen.exe ./cmd/server
if %errorlevel% neq 0 (
    echo [ERROR] Build failed
    exit /b 1
)
echo [OK] Build successful: bin\trafficgen.exe
echo.

REM Run tests
echo [STEP] Running tests...
go test ./... -v
if %errorlevel% neq 0 (
    echo [WARNING] Some tests failed
) else (
    echo [OK] All tests passed
)
echo.

echo ========================================
echo Build verification complete!
echo ========================================
echo.
echo To run the server:
echo   bin\trafficgen.exe -config configs\config.yaml
echo.

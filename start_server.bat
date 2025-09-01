@echo off
echo 🚀 启动流量生成器Web服务器...
echo.

REM 获取脚本所在目录
set "SCRIPT_DIR=%~dp0"
echo 📁 脚本目录: %SCRIPT_DIR%

REM 切换到web/static目录
cd /d "%SCRIPT_DIR%web\static"
echo 📁 当前工作目录: %CD%

REM 检查index.html是否存在
if not exist "index.html" (
    echo ❌ 错误: 在 %CD% 目录下找不到 index.html 文件
    echo.
    echo 💡 请确保在项目根目录下运行此脚本
    pause
    exit /b 1
)

echo ✅ 找到 index.html 文件
echo 🌐 启动HTTP服务器...
echo 📄 访问地址: http://localhost:8080
echo.
echo 💡 按 Ctrl+C 停止服务器
echo.

REM 启动Python HTTP服务器
python -m http.server 8080

pause

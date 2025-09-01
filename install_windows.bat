@echo off
chcp 65001 >nul
echo ========================================
echo HPTG Windows 安装脚本
echo ========================================
echo.

echo 正在检查Python版本...
python --version
if %errorlevel% neq 0 (
    echo 错误：未找到Python，请先安装Python 3.8+
    pause
    exit /b 1
)

echo.
echo 正在创建虚拟环境...
if not exist "venv" (
    python -m venv venv
    echo 虚拟环境创建成功
) else (
    echo 虚拟环境已存在
)

echo.
echo 正在激活虚拟环境...
call venv\Scripts\activate.bat

echo.
echo 正在升级pip...
python -m pip install --upgrade pip

echo.
echo 正在安装依赖包...
echo 选择安装方式：
echo 1. 完整安装（包含开发工具）
echo 2. 最小安装（仅运行必需）
set /p choice="请输入选择 (1 或 2): "

if "%choice%"=="1" (
    echo 正在安装完整依赖...
    pip install -r requirements.txt
) else (
    echo 正在安装最小依赖...
    pip install -r requirements-minimal.txt
)

if %errorlevel% neq 0 (
    echo 错误：依赖安装失败
    pause
    exit /b 1
)

echo.
echo 安装完成！
echo.
echo 启动方式：
echo 1. 直接启动：python web/app.py
echo 2. 使用uvicorn：uvicorn web.app:app --host 0.0.0.0 --port 8080
echo 3. 开发模式：uvicorn web.app:app --reload --host 0.0.0.0 --port 8080
echo.
echo 访问地址：http://localhost:8080
echo.

set /p start="是否现在启动应用？(y/n): "
if /i "%start%"=="y" (
    echo 正在启动应用...
    uvicorn web.app:app --host 0.0.0.0 --port 8080
)

pause

# HPTG Windows PowerShell 安装脚本
# 适用于 Windows 10 + PowerShell 5.0+

param(
    [switch]$Minimal,
    [switch]$Force,
    [string]$PythonVersion = "3.8"
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "HPTG Windows 安装脚本 (PowerShell)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# 检查PowerShell版本
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Host "错误：需要 PowerShell 5.0 或更高版本" -ForegroundColor Red
    exit 1
}

# 检查Python
Write-Host "正在检查Python版本..." -ForegroundColor Yellow
try {
    $pythonVersion = python --version 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Python版本: $pythonVersion" -ForegroundColor Green
    } else {
        throw "Python未找到"
    }
} catch {
    Write-Host "错误：未找到Python，请先安装Python $PythonVersion+" -ForegroundColor Red
    Write-Host "下载地址：https://www.python.org/downloads/" -ForegroundColor Yellow
    exit 1
}

# 创建虚拟环境
Write-Host ""
Write-Host "正在创建虚拟环境..." -ForegroundColor Yellow
if (-not (Test-Path "venv")) {
    python -m venv venv
    Write-Host "虚拟环境创建成功" -ForegroundColor Green
} else {
    Write-Host "虚拟环境已存在" -ForegroundColor Green
}

# 激活虚拟环境
Write-Host ""
Write-Host "正在激活虚拟环境..." -ForegroundColor Yellow
& "venv\Scripts\Activate.ps1"

# 升级pip
Write-Host ""
Write-Host "正在升级pip..." -ForegroundColor Yellow
python -m pip install --upgrade pip

# 选择安装方式
Write-Host ""
if ($Minimal) {
    $choice = "2"
    Write-Host "使用最小安装模式" -ForegroundColor Green
} else {
    Write-Host "选择安装方式：" -ForegroundColor Yellow
    Write-Host "1. 完整安装（包含开发工具）" -ForegroundColor White
    Write-Host "2. 最小安装（仅运行必需）" -ForegroundColor White
    $choice = Read-Host "请输入选择 (1 或 2)"
}

# 安装依赖
Write-Host ""
if ($choice -eq "1") {
    Write-Host "正在安装完整依赖..." -ForegroundColor Yellow
    $requirementsFile = "requirements.txt"
} else {
    Write-Host "正在安装最小依赖..." -ForegroundColor Yellow
    $requirementsFile = "requirements-minimal.txt"
}

try {
    pip install -r $requirementsFile
    if ($LASTEXITCODE -eq 0) {
        Write-Host "依赖安装成功！" -ForegroundColor Green
    } else {
        throw "安装失败"
    }
} catch {
    Write-Host "错误：依赖安装失败" -ForegroundColor Red
    exit 1
}

# 安装完成
Write-Host ""
Write-Host "安装完成！" -ForegroundColor Green
Write-Host ""
Write-Host "启动方式：" -ForegroundColor Cyan
Write-Host "1. 直接启动：python web/app.py" -ForegroundColor White
Write-Host "2. 使用uvicorn：uvicorn web.app:app --host 0.0.0.0 --port 8080" -ForegroundColor White
Write-Host "3. 开发模式：uvicorn web.app:app --reload --host 0.0.0.0 --port 8080" -ForegroundColor White
Write-Host ""
Write-Host "访问地址：http://localhost:8080" -ForegroundColor Cyan
Write-Host ""

# 询问是否启动
$start = Read-Host "是否现在启动应用？(y/n)"
if ($start -eq "y" -or $start -eq "Y") {
    Write-Host "正在启动应用..." -ForegroundColor Yellow
    uvicorn web.app:app --host 0.0.0.0 --port 8080
}

Write-Host ""
Write-Host "安装脚本执行完成！" -ForegroundColor Green

# 流量生成器Web服务器启动脚本
# 可以在任何位置运行，自动找到正确的目录

Write-Host "🚀 启动流量生成器Web服务器..." -ForegroundColor Green
Write-Host ""

# 获取脚本所在目录
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Write-Host "📁 脚本目录: $ScriptDir" -ForegroundColor Yellow

# 查找项目根目录（包含web/static/index.html的目录）
$ProjectRoot = $ScriptDir
while ($ProjectRoot -and -not (Test-Path "$ProjectRoot\web\static\index.html")) {
    $ProjectRoot = Split-Path -Parent $ProjectRoot
}

if (-not $ProjectRoot) {
    Write-Host "❌ 错误: 找不到项目根目录" -ForegroundColor Red
    Write-Host "💡 请确保在项目目录或其子目录下运行此脚本" -ForegroundColor Yellow
    Read-Host "按回车键退出"
    exit 1
}

Write-Host "📁 项目根目录: $ProjectRoot" -ForegroundColor Yellow

# 切换到web/static目录
$StaticDir = "$ProjectRoot\web\static"
Set-Location $StaticDir
Write-Host "📁 当前工作目录: $(Get-Location)" -ForegroundColor Yellow

# 检查index.html
if (-not (Test-Path "index.html")) {
    Write-Host "❌ 错误: 找不到 index.html 文件" -ForegroundColor Red
    exit 1
}

Write-Host "✅ 找到 index.html 文件" -ForegroundColor Green
Write-Host "🌐 启动HTTP服务器..." -ForegroundColor Green
Write-Host "📄 访问地址: http://localhost:8080" -ForegroundColor Cyan
Write-Host ""
Write-Host "💡 按 Ctrl+C 停止服务器" -ForegroundColor Yellow
Write-Host ""

try {
    # 启动Python HTTP服务器
    python -m http.server 8080
} catch {
    Write-Host "❌ 启动失败: $_" -ForegroundColor Red
    exit 1
}

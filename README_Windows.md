# HPTG Windows 10 安装指南

## 🚀 快速开始

### 方法1：使用自动安装脚本（推荐）

#### 使用批处理脚本
```cmd
# 双击运行
install_windows.bat
```

#### 使用PowerShell脚本
```powershell
# 以管理员身份运行PowerShell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
.\install_windows.ps1

# 或者最小安装
.\install_windows.ps1 -Minimal
```

### 方法2：手动安装

#### 1. 环境要求
- Windows 10 (版本 1903 或更高)
- Python 3.8+ 
- PowerShell 5.0+ 或 命令提示符

#### 2. 安装Python
```cmd
# 下载并安装Python 3.8+
# 下载地址：https://www.python.org/downloads/
# 安装时勾选 "Add Python to PATH"
```

#### 3. 创建虚拟环境
```cmd
# 在项目目录下执行
python -m venv venv
venv\Scripts\activate.bat
```

#### 4. 安装依赖
```cmd
# 升级pip
python -m pip install --upgrade pip

# 安装完整依赖（包含开发工具）
pip install -r requirements.txt

# 或者安装最小依赖（仅运行必需）
pip install -r requirements-minimal.txt
```

## 📦 依赖包说明

### 核心依赖
- **fastapi**: Web框架
- **uvicorn**: ASGI服务器
- **pydantic**: 数据验证
- **psutil**: 系统监控
- **numpy**: 数值计算

### 可选依赖
- **pandas**: 数据分析
- **pytest**: 测试框架
- **black**: 代码格式化
- **pywin32**: Windows API访问

## 🚀 启动应用

### 开发模式（推荐）
```cmd
# 激活虚拟环境
venv\Scripts\activate.bat

# 启动应用（自动重载）
uvicorn web.app:app --reload --host 0.0.0.0 --port 8080
```

### 生产模式
```cmd
# 启动应用
uvicorn web.app:app --host 0.0.0.0 --port 8080
```

### 后台运行
```cmd
# 使用nssm安装为Windows服务
nssm install HPTG "C:\path\to\venv\Scripts\python.exe" "C:\path\to\venv\Scripts\uvicorn.exe web.app:app --host 0.0.0.0 --port 8080"
nssm start HPTG
```

## 🌐 访问地址

- **主页面**: http://localhost:8080
- **API文档**: http://localhost:8080/docs
- **静态文件**: http://localhost:8080/static

## 🔧 常见问题

### 1. 端口被占用
```cmd
# 查看端口占用
netstat -ano | findstr :8080

# 结束进程
taskkill /PID <进程ID> /F
```

### 2. 防火墙阻止
- 在Windows防火墙中添加8080端口例外
- 或临时关闭防火墙进行测试

### 3. 权限不足
- 以管理员身份运行命令提示符或PowerShell
- 或使用用户级端口（1024+）

### 4. 虚拟环境激活失败
```cmd
# 重新创建虚拟环境
rmdir /s venv
python -m venv venv
venv\Scripts\activate.bat
```

### 5. 依赖安装失败
```cmd
# 使用国内镜像源
pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple

# 或升级pip
python -m pip install --upgrade pip
```

## 📁 项目结构
```
trafficGenerator/
├── web/                    # Web应用目录
│   ├── app.py             # FastAPI主应用
│   └── static/            # 静态文件
│       └── index.html     # 主页面
├── high_performance_traffic_generator.py  # 核心模块
├── requirements.txt        # 完整依赖
├── requirements-minimal.txt # 最小依赖
├── install_windows.bat    # 批处理安装脚本
├── install_windows.ps1    # PowerShell安装脚本
└── README_Windows.md      # 本文档
```

## 🆘 获取帮助

如果遇到问题，请：
1. 检查Python版本是否为3.8+
2. 确认虚拟环境已激活
3. 查看错误日志
4. 尝试重新安装依赖

## 📝 更新日志

- **v1.0**: 初始版本，支持Windows 10
- 支持Python 3.8+
- 提供自动安装脚本
- 包含完整和最小依赖选项

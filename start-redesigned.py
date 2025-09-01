#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
启动重新设计的流量生成器Web服务
"""

import os
import sys
import subprocess
from pathlib import Path

def main():
    print("🚀 启动重新设计的流量生成器Web服务...")
    print()
    
    # 确保在正确的目录
    script_dir = Path(__file__).parent
    web_dir = script_dir / "web"
    
    if not web_dir.exists():
        print("❌ 找不到web目录")
        return 1
    
    os.chdir(web_dir)
    print(f"📁 工作目录: {os.getcwd()}")
    
    # 检查依赖
    try:
        import fastapi
        import uvicorn
        import psutil
        print("✅ 依赖检查通过")
    except ImportError as e:
        print(f"❌ 缺少依赖: {e}")
        print("💡 请运行: pip install fastapi uvicorn psutil")
        return 1
    
    print("🌐 启动服务器...")
    print("📄 访问地址: http://localhost:5000")
    print("📱 重新设计的界面: http://localhost:5000/")
    print()
    print("💡 按 Ctrl+C 停止服务器")
    print()
    
    try:
        # 启动FastAPI服务器
        subprocess.run([
            sys.executable, "-m", "uvicorn", 
            "app-redesigned:app", 
            "--host", "0.0.0.0", 
            "--port", "5000",
            "--reload"
        ])
    except KeyboardInterrupt:
        print("\n🛑 服务器已停止")
    except Exception as e:
        print(f"❌ 启动失败: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
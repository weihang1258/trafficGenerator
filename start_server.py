#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
流量生成器Web服务器启动脚本
可以在任何位置运行，自动找到正确的目录
"""

import os
import sys
import subprocess
from pathlib import Path

def find_project_root():
    """查找项目根目录"""
    current = Path.cwd()
    
    # 向上查找包含 web/static/index.html 的目录
    for parent in [current] + list(current.parents):
        if (parent / "web" / "static" / "index.html").exists():
            return parent
    
    return None

def main():
    print("🚀 启动流量生成器Web服务器...")
    print()
    
    # 查找项目根目录
    project_root = find_project_root()
    if not project_root:
        print("❌ 错误: 找不到项目根目录")
        print("💡 请确保在项目目录或其子目录下运行此脚本")
        input("按回车键退出...")
        return 1
    
    print(f"📁 项目根目录: {project_root}")
    
    # 切换到web/static目录
    static_dir = project_root / "web" / "static"
    os.chdir(static_dir)
    print(f"📁 当前工作目录: {os.getcwd()}")
    
    # 检查index.html
    if not (static_dir / "index.html").exists():
        print("❌ 错误: 找不到 index.html 文件")
        return 1
    
    print("✅ 找到 index.html 文件")
    print("🌐 启动HTTP服务器...")
    print("📄 访问地址: http://localhost:8080")
    print()
    print("💡 按 Ctrl+C 停止服务器")
    print()
    
    try:
        # 启动Python HTTP服务器
        subprocess.run([sys.executable, "-m", "http.server", "8080"])
    except KeyboardInterrupt:
        print("\n🛑 服务器已停止")
    except Exception as e:
        print(f"❌ 启动失败: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())

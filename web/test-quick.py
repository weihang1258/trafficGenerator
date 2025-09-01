#!/usr/bin/env python3
"""
快速测试脚本 - 修复后的版本测试
"""

import os
import webbrowser
from http.server import HTTPServer, SimpleHTTPRequestHandler
import threading
import time

class QuickTestHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory="static", **kwargs)
    
    def log_message(self, format, *args):
        # 简化日志输出
        print(f"[{time.strftime('%H:%M:%S')}] {format % args}")

def start_server():
    """启动HTTP服务器"""
    port = 8080
    server = HTTPServer(('localhost', port), QuickTestHandler)
    print(f"✅ 服务器启动成功: http://localhost:{port}")
    server.serve_forever()

def main():
    print("🔧 Vue.js 修复后的快速测试")
    print("=" * 50)
    
    # 确保在正确目录
    web_dir = os.path.dirname(__file__)
    if web_dir:
        os.chdir(web_dir)
    
    print(f"📁 工作目录: {os.getcwd()}")
    
    # 检查文件
    files = ["static/index-redesigned.html", "static/debug.html", "static/simple-test.html"]
    for f in files:
        if os.path.exists(f):
            print(f"✅ 找到文件: {f}")
        else:
            print(f"❌ 缺少文件: {f}")
    
    print()
    print("🚀 启动测试服务器...")
    
    # 在后台启动服务器
    server_thread = threading.Thread(target=start_server, daemon=True)
    server_thread.start()
    
    # 等待服务器启动
    time.sleep(1)
    
    print("🌐 可用的测试页面:")
    pages = [
        ("修复后的主页面", "http://localhost:8080/index-redesigned.html"),
        ("调试页面", "http://localhost:8080/debug.html"), 
        ("简单测试页面", "http://localhost:8080/simple-test.html")
    ]
    
    for name, url in pages:
        print(f"  • {name}: {url}")
    
    print()
    print("🔍 修复内容:")
    print("  • 修复了 formatTuple 函数定义")
    print("  • 添加了空值检查")
    print("  • 完善了方法定义")
    print("  • 增加了更多示例数据")
    print("  • 改进了CSS样式")
    
    # 自动打开浏览器
    print("\n🚀 正在自动打开浏览器...")
    webbrowser.open("http://localhost:8080/index-redesigned.html")
    
    try:
        print("\n💡 按 Ctrl+C 停止服务器")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 服务器已停止")

if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""
简单测试服务器
"""

import os
from http.server import HTTPServer, SimpleHTTPRequestHandler
import webbrowser

class CustomHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory="static", **kwargs)

def main():
    port = 8080
    
    # 确保在正确目录
    web_dir = os.path.dirname(__file__)
    if web_dir:
        os.chdir(web_dir)
    
    print(f"🚀 启动简单HTTP服务器...")
    print(f"📁 服务目录: {os.path.join(os.getcwd(), 'static')}")
    print(f"🌐 访问地址: http://localhost:{port}")
    print(f"🔧 调试页面: http://localhost:{port}/debug.html")
    print(f"🎨 重新设计: http://localhost:{port}/index-redesigned.html")
    print()
    print("💡 按 Ctrl+C 停止服务器")
    
    try:
        server = HTTPServer(('localhost', port), CustomHandler)
        print(f"✅ 服务器启动成功，端口: {port}")
        
        # 自动打开浏览器
        webbrowser.open(f'http://localhost:{port}/debug.html')
        
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n🛑 服务器已停止")
    except Exception as e:
        print(f"❌ 启动失败: {e}")

if __name__ == "__main__":
    main()
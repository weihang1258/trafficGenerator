from flask import Flask, send_from_directory, render_template_string
import os

app = Flask(__name__)

# 设置静态文件目录
app.static_folder = 'static'
app.static_url_path = '/static'

@app.route('/')
def index():
    """主页面路由"""
    return send_from_directory('static', 'index.html')

@app.route('/<path:filename>')
def static_files(filename):
    """静态文件路由"""
    return send_from_directory('static', filename)

@app.route('/ws')
def websocket():
    """WebSocket端点（如果需要）"""
    return "WebSocket endpoint"

if __name__ == '__main__':
    print("🚀 启动Flask服务器...")
    print("📁 静态文件目录:", os.path.abspath('static'))
    print("🌐 访问地址: http://localhost:5000")
    print("📄 主页面: http://localhost:5000/")
    app.run(host='0.0.0.0', port=5000, debug=True)



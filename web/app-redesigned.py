#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
重新设计的Web应用后端
基于FastAPI，支持策略管理、任务管理等新功能
"""

from fastapi import FastAPI, HTTPException, WebSocket
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel
from typing import List, Dict, Optional, Any
import json
import os
import asyncio
import time
import uuid
from datetime import datetime
import logging

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 导入现有的流量生成器
try:
    from high_performance_traffic_generator import HighPerformanceTrafficGenerator
except ImportError:
    # 如果导入失败，创建一个模拟类
    class HighPerformanceTrafficGenerator:
        def __init__(self, **kwargs):
            self.is_running = False
        def start(self): self.is_running = True
        def stop(self): self.is_running = False
        def get_buffer_status(self): 
            return {"is_running": self.is_running, "current_size": 0}

app = FastAPI(title="高性能流量生成器", version="2.0.0")

# 静态文件服务 - 确保路径正确
static_dir = os.path.join(os.path.dirname(__file__), "static")
if not os.path.exists(static_dir):
    static_dir = "static"
    
logger.info(f"静态文件目录: {os.path.abspath(static_dir)}")
app.mount("/static", StaticFiles(directory=static_dir), name="static")

# 全局变量
hptg = None
strategies_db = {}
tasks_db = {}
system_config = {
    "flow_count": 0,
    "duration": 10,
    "output_mode": "pcap",
    "pcap_path": "C:\\temp\\pcap\\",
    "config_processes": 2,
    "packet_processes": 2,
    "buffer_size": 10000
}

# 数据模型
class TupleConfig(BaseModel):
    src_ip: str = "192.168.1.1"
    dst_ip: str = "10.0.0.1" 
    src_port: str = "1024"
    dst_port: str = "80"
    protocol: str = "TCP"
    src_ip_strategy: str = "fixed"  # fixed, range, random, list
    dst_ip_strategy: str = "fixed"
    src_port_strategy: str = "fixed"
    dst_port_strategy: str = "fixed"

class Strategy(BaseModel):
    id: Optional[str] = None
    name: str
    protocol: str  # TCP, UDP, HTTP, HTTPS, MIX
    description: Optional[str] = ""
    enabled: bool = True
    tuple_config: TupleConfig
    protocol_config: Dict[str, Any] = {}
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    created_by: str = "admin"
    usage_count: int = 0
    tags: List[str] = []

class Task(BaseModel):
    id: Optional[str] = None
    name: str
    description: Optional[str] = ""
    strategy_ids: List[str]
    global_config: Dict[str, Any] = {}
    status: str = "waiting"  # waiting, running, paused, completed, failed
    progress: float = 0.0
    created_at: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    config_file_path: Optional[str] = None
    output_file_path: Optional[str] = None
    statistics: Dict[str, Any] = {}

class SystemStatus(BaseModel):
    running: bool = False
    active_tasks: int = 0
    queue_depth: int = 0
    buffer_usage: float = 0.0
    traffic_rate: float = 0.0
    packet_count: int = 0
    cpu_usage: float = 0.0
    memory_usage: float = 0.0

@app.get("/routes", response_class=HTMLResponse)
async def list_routes():
    """显示所有可用的路由"""
    routes_html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>可用路由</title>
        <style>
            body { background: #0f1419; color: #f0f6fc; font-family: Arial, sans-serif; padding: 20px; }
            .route { background: #1e2329; padding: 15px; margin: 10px 0; border-radius: 8px; }
            a { color: #58a6ff; text-decoration: none; }
            a:hover { text-decoration: underline; }
        </style>
    </head>
    <body>
        <h1>🚀 可用路由列表</h1>
        
        <div class="route">
            <h3>🏠 页面访问</h3>
            <p><a href="/">首页 (调试页面)</a></p>
            <p><a href="/debug">调试页面</a></p>
            <p><a href="/redesigned">重新设计页面</a></p>
            <p><a href="/index.html">原版页面</a></p>
            <p><a href="/index-redesigned.html">重新设计页面 (HTML)</a></p>
        </div>
        
        <div class="route">
            <h3>🔧 API接口</h3>
            <p><a href="/api/test">测试API</a></p>
            <p><a href="/api/hptg/status">系统状态</a></p>
            <p><a href="/api/strategies">策略列表</a></p>
            <p><a href="/api/tasks">任务列表</a></p>
        </div>
        
        <div class="route">
            <h3>📁 静态文件</h3>
            <p><a href="/static/debug.html">调试页面 (静态)</a></p>
            <p><a href="/static/simple-test.html">简单测试页面</a></p>
            <p><a href="/static/index-redesigned.html">重新设计页面 (静态)</a></p>
        </div>
        
        <div class="route">
            <h3>📊 其他信息</h3>
            <p>服务器地址: http://localhost:5000</p>
            <p>静态文件目录: {static_dir}</p>
        </div>
    </body>
    </html>
    """.format(static_dir=static_dir)
    
    return HTMLResponse(routes_html)

@app.get("/api/test")
async def test_api():
    """测试API连接"""
    return {
        "message": "API连接成功",
        "timestamp": datetime.now().isoformat(),
        "status": "ok",
        "version": "2.0.0"
    }
@app.get("/", response_class=HTMLResponse)
async def root():
    """根路径重定向到调试页面"""
    try:
        debug_file = os.path.join(static_dir, "debug.html")
        if os.path.exists(debug_file):
            logger.info(f"返回调试页面: {debug_file}")
            return FileResponse(debug_file)
        else:
            return HTMLResponse("<h1>调试页面不存在</h1><p>请检查文件路径</p>")
    except Exception as e:
        logger.error(f"加载页面失败: {e}")
        return HTMLResponse(f"<h1>加载失败</h1><p>{str(e)}</p>")

@app.get("/debug", response_class=HTMLResponse)
async def debug_page():
    """调试页面"""
    return FileResponse(os.path.join(static_dir, "debug.html"))

@app.get("/redesigned", response_class=HTMLResponse) 
async def redesigned_page():
    """重新设计的页面"""
    return FileResponse(os.path.join(static_dir, "index-redesigned.html"))

@app.get("/index.html", response_class=HTMLResponse)
async def index_page():
    """原版index.html页面"""
    index_file = os.path.join(static_dir, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    else:
        return HTMLResponse("<h1>原版页面不存在</h1><p>请检查index.html文件</p>", status_code=404)

@app.get("/index-redesigned.html", response_class=HTMLResponse)
async def redesigned_html_page():
    """重新设计页面的直接访问"""
    redesigned_file = os.path.join(static_dir, "index-redesigned.html")
    if os.path.exists(redesigned_file):
        return FileResponse(redesigned_file)
    else:
        return HTMLResponse("<h1>重新设计页面不存在</h1><p>请检查index-redesigned.html文件</p>", status_code=404)

# 策略管理API
@app.get("/api/strategies", response_model=List[Strategy])
async def get_strategies():
    """获取所有策略列表"""
    return list(strategies_db.values())

@app.post("/api/strategies", response_model=Strategy)
async def create_strategy(strategy: Strategy):
    """创建新策略"""
    strategy.id = str(uuid.uuid4())
    strategy.created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    strategy.updated_at = strategy.created_at
    strategies_db[strategy.id] = strategy
    save_strategies_to_file()
    return strategy

@app.get("/api/strategies/{strategy_id}", response_model=Strategy)
async def get_strategy(strategy_id: str):
    """获取单个策略详情"""
    if strategy_id not in strategies_db:
        raise HTTPException(status_code=404, detail="策略不存在")
    return strategies_db[strategy_id]

@app.put("/api/strategies/{strategy_id}", response_model=Strategy)
async def update_strategy(strategy_id: str, strategy: Strategy):
    """更新策略"""
    if strategy_id not in strategies_db:
        raise HTTPException(status_code=404, detail="策略不存在")
    strategy.id = strategy_id
    strategy.updated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    strategies_db[strategy_id] = strategy
    save_strategies_to_file()
    return strategy

@app.delete("/api/strategies/{strategy_id}")
async def delete_strategy(strategy_id: str):
    """删除策略"""
    if strategy_id not in strategies_db:
        raise HTTPException(status_code=404, detail="策略不存在")
    del strategies_db[strategy_id]
    save_strategies_to_file()
    return {"message": "策略已删除"}

@app.post("/api/strategies/batch")
async def batch_strategy_operation(operation: str, strategy_ids: List[str]):
    """批量策略操作"""
    if operation == "enable":
        for sid in strategy_ids:
            if sid in strategies_db:
                strategies_db[sid].enabled = True
    elif operation == "disable":
        for sid in strategy_ids:
            if sid in strategies_db:
                strategies_db[sid].enabled = False
    elif operation == "delete":
        for sid in strategy_ids:
            if sid in strategies_db:
                del strategies_db[sid]
    
    save_strategies_to_file()
    return {"message": f"批量{operation}操作完成"}

# 任务管理API
@app.get("/api/tasks", response_model=List[Task])
async def get_tasks():
    """获取所有任务列表"""
    return list(tasks_db.values())

@app.post("/api/tasks", response_model=Task)
async def create_task(task: Task):
    """创建新任务"""
    task.id = str(uuid.uuid4())
    task.created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # 生成配置文件
    config_file_path = generate_task_config(task)
    task.config_file_path = config_file_path
    
    tasks_db[task.id] = task
    save_tasks_to_file()
    return task

@app.put("/api/tasks/{task_id}/start")
async def start_task(task_id: str):
    """启动任务"""
    if task_id not in tasks_db:
        raise HTTPException(status_code=404, detail="任务不存在")
    
    task = tasks_db[task_id]
    if task.status != "waiting":
        raise HTTPException(status_code=400, detail="任务状态不允许启动")
    
    # 启动流量生成器
    if not hptg or not hptg.is_running:
        await start_hptg()
    
    # 加载任务配置并执行
    success = await execute_task(task)
    if success:
        task.status = "running"
        task.started_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        tasks_db[task_id] = task
        save_tasks_to_file()
        return {"message": "任务启动成功"}
    else:
        raise HTTPException(status_code=500, detail="任务启动失败")

@app.put("/api/tasks/{task_id}/stop")
async def stop_task(task_id: str):
    """停止任务"""
    if task_id not in tasks_db:
        raise HTTPException(status_code=404, detail="任务不存在")
    
    task = tasks_db[task_id]
    task.status = "stopped"
    task.completed_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    tasks_db[task_id] = task
    save_tasks_to_file()
    return {"message": "任务停止成功"}

@app.post("/api/tasks/{task_id}/refresh-config")
async def refresh_task_config(task_id: str):
    """刷新任务配置"""
    if task_id not in tasks_db:
        raise HTTPException(status_code=404, detail="任务不存在")
    
    task = tasks_db[task_id]
    
    # 检查绑定的策略是否还存在
    missing_strategies = []
    for strategy_id in task.strategy_ids:
        if strategy_id not in strategies_db:
            missing_strategies.append(strategy_id)
    
    if missing_strategies:
        raise HTTPException(
            status_code=400, 
            detail=f"以下策略不存在: {', '.join(missing_strategies)}"
        )
    
    # 重新生成配置文件
    config_file_path = generate_task_config(task)
    task.config_file_path = config_file_path
    task.updated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    tasks_db[task_id] = task
    save_tasks_to_file()
    return {"message": "配置刷新成功", "config_file": config_file_path}

# 系统控制API
@app.post("/api/hptg/start")
async def start_hptg():
    """启动高性能流量生成器"""
    global hptg
    try:
        hptg = HighPerformanceTrafficGenerator(
            config_processes=system_config["config_processes"],
            packet_processes=system_config["packet_processes"],
            buffer_size=system_config["buffer_size"]
        )
        hptg.start()
        return {"message": "流量生成器启动成功"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"启动失败: {str(e)}")

@app.post("/api/hptg/stop")
async def stop_hptg():
    """停止高性能流量生成器"""
    global hptg
    try:
        if hptg:
            hptg.stop()
        return {"message": "流量生成器停止成功"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"停止失败: {str(e)}")

@app.get("/api/hptg/status", response_model=SystemStatus)
async def get_system_status():
    """获取系统状态"""
    status = SystemStatus()
    
    if hptg:
        buffer_status = hptg.get_buffer_status()
        status.running = buffer_status.get("is_running", False)
        status.buffer_usage = buffer_status.get("current_size", 0) / buffer_status.get("buffer_size", 1) * 100
        status.queue_depth = buffer_status.get("config_queue_depth", 0)
    
    status.active_tasks = len([t for t in tasks_db.values() if t.status == "running"])
    
    # 模拟其他指标（实际项目中应该从系统获取真实数据）
    import psutil
    status.cpu_usage = psutil.cpu_percent()
    status.memory_usage = round(psutil.virtual_memory().used / (1024**3), 1)
    
    return status

@app.get("/api/system/config")
async def get_system_config():
    """获取系统配置"""
    return system_config

@app.put("/api/system/config")
async def update_system_config(config: Dict[str, Any]):
    """更新系统配置"""
    global system_config
    system_config.update(config)
    save_system_config()
    return {"message": "配置更新成功"}

# WebSocket for real-time updates
@app.websocket("/api/hptg/stream")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            status = await get_system_status()
            await websocket.send_text(status.json())
            await asyncio.sleep(1)  # 每秒发送一次状态更新
    except Exception as e:
        print(f"WebSocket连接错误: {e}")

# 辅助函数
def generate_task_config(task: Task) -> str:
    """生成任务的JSON配置文件"""
    config = {
        "task_id": task.id,
        "task_name": task.name,
        "global_config": {
            "flow_count": system_config.get("flow_count", 0),
            "duration_minutes": system_config.get("duration", 10),
            "output_mode": system_config.get("output_mode", "pcap"),
            "pcap_path": system_config.get("pcap_path", "C:\\temp\\pcap\\")
        },
        "strategies": []
    }
    
    # 添加策略配置
    for strategy_id in task.strategy_ids:
        if strategy_id in strategies_db:
            strategy = strategies_db[strategy_id]
            strategy_config = {
                "strategy_id": strategy.id,
                "strategy_name": strategy.name,
                "type": strategy.protocol.lower(),
                "config": {
                    "tuple": strategy.tuple_config.dict(),
                    "protocol": strategy.protocol_config
                }
            }
            config["strategies"].append(strategy_config)
    
    # 保存配置文件
    config_dir = "configs"
    os.makedirs(config_dir, exist_ok=True)
    config_file_path = os.path.join(config_dir, f"task_{task.id}.json")
    
    with open(config_file_path, 'w', encoding='utf-8') as f:
        json.dump(config, f, ensure_ascii=False, indent=2)
    
    return config_file_path

async def execute_task(task: Task) -> bool:
    """执行任务"""
    try:
        # 这里应该调用实际的流量生成逻辑
        # 暂时返回True表示成功
        return True
    except Exception as e:
        print(f"任务执行失败: {e}")
        return False

def save_strategies_to_file():
    """保存策略到文件"""
    with open("strategies.json", 'w', encoding='utf-8') as f:
        data = {sid: strategy.dict() for sid, strategy in strategies_db.items()}
        json.dump(data, f, ensure_ascii=False, indent=2)

def load_strategies_from_file():
    """从文件加载策略"""
    try:
        with open("strategies.json", 'r', encoding='utf-8') as f:
            data = json.load(f)
            for sid, strategy_data in data.items():
                strategies_db[sid] = Strategy(**strategy_data)
    except FileNotFoundError:
        pass

def save_tasks_to_file():
    """保存任务到文件"""
    with open("tasks.json", 'w', encoding='utf-8') as f:
        data = {tid: task.dict() for tid, task in tasks_db.items()}
        json.dump(data, f, ensure_ascii=False, indent=2)

def load_tasks_from_file():
    """从文件加载任务"""
    try:
        with open("tasks.json", 'r', encoding='utf-8') as f:
            data = json.load(f)
            for tid, task_data in data.items():
                tasks_db[tid] = Task(**task_data)
    except FileNotFoundError:
        pass

def save_system_config():
    """保存系统配置"""
    with open("system_config.json", 'w', encoding='utf-8') as f:
        json.dump(system_config, f, ensure_ascii=False, indent=2)

def load_system_config():
    """加载系统配置"""
    global system_config
    try:
        with open("system_config.json", 'r', encoding='utf-8') as f:
            loaded_config = json.load(f)
            system_config.update(loaded_config)
    except FileNotFoundError:
        pass

# 启动时加载数据
@app.on_event("startup")
async def startup_event():
    logger.info("🚀 启动后端服务...")
    logger.info(f"📁 工作目录: {os.getcwd()}")
    logger.info(f"📁 静态文件目录: {os.path.abspath(static_dir)}")
    
    # 检查关键文件
    files_to_check = [
        "debug.html",
        "index-redesigned.html", 
        "index.html"
    ]
    
    for file in files_to_check:
        file_path = os.path.join(static_dir, file)
        if os.path.exists(file_path):
            logger.info(f"✅ 找到文件: {file}")
        else:
            logger.warning(f"⚠️  未找到文件: {file}")
    
    load_strategies_from_file()
    load_tasks_from_file()  
    load_system_config()
    
    # 创建示例数据（如果没有数据的话）
    if not strategies_db:
        logger.info("📋 创建示例数据...")
        create_sample_data()
    
    logger.info("✅ 后端服务启动完成")

def create_sample_data():
    """创建示例数据"""
    # 示例策略
    sample_strategies = [
        Strategy(
            id="strategy_1",
            name="Web压力测试-1",
            protocol="HTTP",
            description="Web服务器压力测试策略",
            tuple_config=TupleConfig(
                src_ip="192.168.1.0/24",
                dst_ip="10.0.0.1",
                src_port="10000-20000",
                dst_port="80,443",
                protocol="HTTP",
                src_ip_strategy="random",
                dst_ip_strategy="fixed",
                src_port_strategy="range",
                dst_port_strategy="list"
            ),
            created_at="2024-01-15 14:30:25",
            usage_count=28
        ),
        Strategy(
            id="strategy_2", 
            name="TCP批量传输-A",
            protocol="TCP",
            description="TCP批量数据传输测试",
            tuple_config=TupleConfig(
                src_ip="192.168.1.100-200",
                dst_ip="172.16.0.0/16", 
                src_port="1024-65535",
                dst_port="80",
                protocol="TCP",
                src_ip_strategy="range",
                dst_ip_strategy="random",
                src_port_strategy="random",
                dst_port_strategy="fixed"
            ),
            created_at="2024-01-14 10:15:30",
            usage_count=15
        )
    ]
    
    for strategy in sample_strategies:
        strategies_db[strategy.id] = strategy
    
    save_strategies_to_file()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)
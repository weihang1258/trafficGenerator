#!/usr/bin/env python3
import sys
import os

# 添加项目根目录到Python路径
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# 导入应用
from web.app import app

print("=== FastAPI App Routes Debug ===")
print(f"App title: {app.title}")
print(f"App version: {app.version}")

print("\n=== All Routes ===")
for route in app.routes:
    if hasattr(route, 'path'):
        print(f"Path: {route.path}")
        if hasattr(route, 'endpoint'):
            print(f"  Endpoint: {route.endpoint.__name__}")
        if hasattr(route, 'methods'):
            print(f"  Methods: {route.methods}")
        print()

print("\n=== API Routes Only ===")
api_routes = [route for route in app.routes if hasattr(route, 'path') and route.path.startswith('/api/')]
for route in api_routes:
    print(f"API: {route.path}")
    if hasattr(route, 'endpoint'):
        print(f"  Function: {route.endpoint.__name__}")
    if hasattr(route, 'methods'):
        print(f"  Methods: {route.methods}")
    print()

print(f"\nTotal routes: {len(app.routes)}")
print(f"API routes: {len(api_routes)}")

#!/usr/bin/env python3
import sys
import os

# 添加项目根目录到Python路径
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# 导入应用
from web.app import app

print("=== Testing Route Registration ===")

# 检查所有路由
print("\nAll routes:")
for route in app.routes:
    if hasattr(route, 'path'):
        print(f"  {route.path}")
        if hasattr(route, 'endpoint'):
            print(f"    Endpoint: {route.endpoint.__name__}")
        if hasattr(route, 'methods'):
            print(f"    Methods: {route.methods}")

# 检查特定路由
print("\n=== Checking /api/hptg/status ===")
status_routes = [r for r in app.routes if hasattr(r, 'path') and r.path == '/api/hptg/status']
print(f"Found {len(status_routes)} status routes")

if status_routes:
    route = status_routes[0]
    print(f"Route: {route}")
    print(f"Endpoint: {route.endpoint}")
    print(f"Methods: {getattr(route, 'methods', 'N/A')}")
    
    # 尝试调用函数
    try:
        result = route.endpoint()
        print(f"Function result: {result}")
    except Exception as e:
        print(f"Function error: {e}")
else:
    print("No status routes found!")

# 检查是否有重复路由
print("\n=== Checking for duplicate routes ===")
paths = [r.path for r in app.routes if hasattr(r, 'path')]
duplicates = [p for p in set(paths) if paths.count(p) > 1]
if duplicates:
    print(f"Duplicate paths: {duplicates}")
else:
    print("No duplicate paths found")

print("\n=== Route count by path ===")
for path in sorted(set(paths)):
    count = paths.count(path)
    print(f"  {path}: {count} routes")

#!/usr/bin/env python3
from fastapi import FastAPI
import uvicorn

app = FastAPI(title="Simple Test", version="1.0")

@app.get("/")
def root():
    return {"message": "Hello World"}

@app.get("/api/hptg/status")
def api_status():
    return {"running": False, "test": True}

@app.get("/api/test")
def api_test():
    return {"message": "Test API"}

if __name__ == "__main__":
    print("=== Simple Test App ===")
    print("Available routes:")
    for route in app.routes:
        if hasattr(route, 'path'):
            print(f"  {route.path}")
    
    print("\nStarting server on http://localhost:8003")
    uvicorn.run(app, host="0.0.0.0", port=8003, log_level="info")

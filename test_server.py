#!/usr/bin/env python3
import uvicorn
from web.app import app

if __name__ == "__main__":
    print("Starting test server...")
    print("Available routes:")
    for route in app.routes:
        if hasattr(route, 'path'):
            print(f"  {route.path}")
    
    print("\nStarting server on http://localhost:8001")
    uvicorn.run(app, host="0.0.0.0", port=8001)

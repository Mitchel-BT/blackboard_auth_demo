"""
Blackboard MCP Server Entry Point
OAuth handled automatically by FastMCP OAuthProxy
"""
import os
from dotenv import load_dotenv
from blackboard_mcp import mcp

load_dotenv()

if __name__ == "__main__":
    import uvicorn
    
    # Get ASGI app from FastMCP (includes OAuth routes automatically)
    app = mcp.get_asgi_app()
    
    port = int(os.getenv("PORT", 8000))
    
    print("\n" + "="*60)
    print("🚀 BLACKBOARD MCP SERVER")
    print("="*60)
    print(f"Server URL: http://localhost:{port}")
    print(f"MCP Endpoint: http://localhost:{port}/mcp")
    print(f"OAuth: Handled automatically by FastMCP OAuthProxy")
    print("="*60 + "\n")
    
    uvicorn.run(app, host="0.0.0.0", port=port)
```

## 5. Keep `blackboard_client.py` as is

Your existing `blackboard_client.py` doesn't need changes.

## 6. Delete these files (no longer needed)

- `session_middleware.py` - OAuthProxy handles sessions
- `templates.py` - OAuthProxy generates pages
- Any custom auth route handlers

## 7. Update environment variables in FastMCP Cloud

Make sure these are set:
```
BLACKBOARD_URL=https://your-school.blackboard.com
BLACKBOARD_APP_KEY=your-app-key
BLACKBOARD_APP_SECRET=your-app-secret
SERVER_URL=https://your-project.fastmcp.cloud
```

(Remove `TOKEN_ENCRYPTION_KEY` - not needed)

## 8. Update Blackboard Developer Portal

Make sure your redirect URI is set to:
```
https://your-project.fastmcp.cloud/oauth/callback

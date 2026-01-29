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
    
    print("")
    print("=" * 60)
    print("🚀 BLACKBOARD MCP SERVER")
    print("=" * 60)
    print(f"Server URL: http://localhost:{port}")
    print(f"MCP Endpoint: http://localhost:{port}/mcp")
    print("OAuth: Handled automatically by FastMCP OAuthProxy")
    print("=" * 60)
    print("")
    
    uvicorn.run(app, host="0.0.0.0", port=port)

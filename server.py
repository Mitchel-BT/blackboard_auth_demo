"""
Local dev entry point (NOT used by FastMCP Cloud).
FastMCP Cloud entrypoint should be: blackboard_mcp.py:mcp
"""

import os
from dotenv import load_dotenv
from blackboard_mcp import mcp

load_dotenv()

if __name__ == "__main__":
    import uvicorn

    app = mcp.get_asgi_app()
    port = int(os.getenv("PORT", 8000))

    print(f"Local server: http://localhost:{port}")
    print(f"MCP endpoint:  http://localhost:{port}/mcp")

    uvicorn.run(app, host="0.0.0.0", port=port)

import os
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, RedirectResponse
from auth import token_manager
from blackboard_client import BlackboardClient
from blackboard_mcp import mcp
from session_middleware import MCPSessionMiddleware

load_dotenv()

# Create FastAPI app
app = FastAPI()

# Add our custom session middleware FIRST
app.add_middleware(MCPSessionMiddleware)

# Mount MCP server
app.mount("/mcp", mcp.streamable_http_app())

@app.get("/")
async def root():
    """Health check"""
    return {
        "status": "ok",
        "server": "Blackboard MCP (Hybrid)",
        "active_sessions": token_manager.get_session_count(),
        "mcp_endpoint": "/mcp"
    }

@app.get("/auth/start")
async def start_auth(session: str):
    """Start Blackboard OAuth flow"""
    blackboard_url = os.getenv("BLACKBOARD_URL")
    app_key = os.getenv("BLACKBOARD_APP_KEY")
    server_url = os.getenv("SERVER_URL")
    
    callback_url = f"{server_url}/auth/callback"
    
    auth_url = (
        f"{blackboard_url}/learn/api/public/v1/oauth2/authorizationcode"
        f"?client_id={app_key}"
        f"&redirect_uri={callback_url}"
        f"&response_type=code"
        f"&scope=read write"
        f"&state={session}"
    )
    
    return RedirectResponse(url=auth_url)

@app.get("/auth/callback")
async def auth_callback(code: str, state: str):
    """Handle Blackboard OAuth callback"""
    auth_session_id = state
    
    try:
        blackboard_client = BlackboardClient(
            base_url=os.getenv("BLACKBOARD_URL"),
            app_key=os.getenv("BLACKBOARD_APP_KEY"),
            app_secret=os.getenv("BLACKBOARD_APP_SECRET")
        )
        
        server_url = os.getenv("SERVER_URL")
        callback_url = f"{server_url}/auth/callback"
        
        token = await blackboard_client.exchange_code_for_token(code, callback_url)
        await token_manager.store_auth_token(auth_session_id, token)
        
        return HTMLResponse(f"""
        <!DOCTYPE html>
        <html>
            <head>
                <title>✅ Success</title>
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <style>
                    body {{
                        font-family: Arial, sans-serif;
                        max-width: 600px;
                        margin: 100px auto;
                        padding: 20px;
                        text-align: center;
                    }}
                    .code {{
                        background: #f0f0f0;
                        padding: 20px;
                        font-family: monospace;
                        border-radius: 4px;
                        margin: 20px 0;
                        word-break: break-all;
                    }}
                    button {{
                        background: #4CAF50;
                        color: white;
                        padding: 12px 24px;
                        border: none;
                        border-radius: 4px;
                        cursor: pointer;
                    }}
                </style>
            </head>
            <body>
                <h1>✅ Authentication Successful!</h1>
                <p>Copy this code:</p>
                <div class="code" id="code">{auth_session_id}</div>
                <button onclick="navigator.clipboard.writeText(document.getElementById('code').textContent); this.textContent='✅ Copied!'">
                    📋 Copy Code
                </button>
            </body>
        </html>
        """)
        
    except Exception as e:
        return HTMLResponse(f"<h1>❌ Error</h1><p>{str(e)}</p>", status_code=400)

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    print(f"🚀 Starting Blackboard MCP (Hybrid Mode)")
    print(f"📍 MCP endpoint: http://localhost:{port}/mcp")
    uvicorn.run(app, host="0.0.0.0", port=port)

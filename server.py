import os
from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastmcp import FastMCP
from auth import token_manager
from blackboard_client import BlackboardClient

load_dotenv()

# Create FastAPI app for web routes
app = FastAPI()

# Create FastMCP server
from blackboard_mcp import mcp

# Mount MCP at /mcp endpoint
app.mount("/mcp", mcp.get_asgi_app())

# OAuth routes
@app.get("/")
async def root():
    return {
        "status": "ok",
        "server": "Blackboard MCP",
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
                <title>✅ Authentication Successful</title>
                <style>
                    body {{
                        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        min-height: 100vh;
                        margin: 0;
                        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    }}
                    .container {{
                        background: white;
                        padding: 40px;
                        border-radius: 12px;
                        box-shadow: 0 10px 40px rgba(0,0,0,0.2);
                        max-width: 500px;
                        text-align: center;
                    }}
                    h1 {{ color: #2d3748; margin-bottom: 20px; }}
                    .code {{
                        background: #f7fafc;
                        padding: 20px;
                        font-size: 16px;
                        font-family: 'Courier New', monospace;
                        margin: 20px 0;
                        border-radius: 8px;
                        word-break: break-all;
                        border: 2px solid #e2e8f0;
                    }}
                    button {{
                        background: #667eea;
                        color: white;
                        padding: 12px 24px;
                        border: none;
                        border-radius: 6px;
                        cursor: pointer;
                        font-size: 16px;
                        font-weight: 600;
                    }}
                    button:hover {{ background: #5a67d8; }}
                    .instructions {{
                        color: #4a5568;
                        margin: 20px 0;
                        line-height: 1.6;
                    }}
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>✅ Authentication Successful!</h1>
                    <div class="instructions">
                        <p>Copy this code and paste it back to Claude:</p>
                    </div>
                    <div class="code" id="code">{auth_session_id}</div>
                    <button onclick="copyCode()">📋 Copy Code</button>
                    <p style="margin-top: 20px; color: #718096; font-size: 14px;">
                        You can close this window after copying the code.
                    </p>
                </div>
                <script>
                    function copyCode() {{
                        const code = document.getElementById('code').textContent;
                        navigator.clipboard.writeText(code).then(() => {{
                            const button = document.querySelector('button');
                            button.textContent = '✅ Copied!';
                            setTimeout(() => {{
                                button.textContent = '📋 Copy Code';
                            }}, 2000);
                        }});
                    }}
                </script>
            </body>
        </html>
        """)
        
    except Exception as e:
        return HTMLResponse(f"""
        <html>
            <body style="font-family: Arial; padding: 50px; text-align: center;">
                <h1>❌ Authentication Failed</h1>
                <p>Error: {str(e)}</p>
            </body>
        </html>
        """, status_code=400)

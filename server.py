"""
Blackboard MCP Server with Two-Stage Authentication

Stage 1: FastMCP Cloud SSO (automatic - protects the server)
Stage 2: Blackboard OAuth (per-session, auto-completing)
"""
import os
import secrets
import httpx
from datetime import datetime, timedelta
from fastmcp import FastMCP, Context

# =============================================================================
# Configuration
# =============================================================================

BLACKBOARD_URL = os.environ["BLACKBOARD_URL"].rstrip("/")
BLACKBOARD_APP_KEY = os.environ["BLACKBOARD_APP_KEY"]
BLACKBOARD_APP_SECRET = os.environ["BLACKBOARD_APP_SECRET"]
SERVER_URL = os.environ["SERVER_URL"].rstrip("/")

# =============================================================================
# In-Memory Storage (session-scoped, multi-tenant safe)
# =============================================================================

# Maps session_id -> {access_token, expires_at, blackboard_user_id}
_session_tokens: dict[str, dict] = {}

# Maps auth_state -> {session_id, created_at} for pending OAuth flows
_pending_auth: dict[str, dict] = {}

# =============================================================================
# Auth Helpers
# =============================================================================

def get_session_token(session_id: str) -> str | None:
    """Get Blackboard access token for a session, if valid."""
    data = _session_tokens.get(session_id)
    if not data:
        return None
    
    # Check expiration
    if datetime.utcnow() >= data["expires_at"]:
        del _session_tokens[session_id]
        return None
    
    return data["access_token"]


def is_authenticated(session_id: str) -> bool:
    """Check if session has valid Blackboard auth."""
    return get_session_token(session_id) is not None


def create_auth_state(session_id: str) -> str:
    """Create a state token for OAuth flow, linked to session."""
    state = secrets.token_urlsafe(32)
    _pending_auth[state] = {
        "session_id": session_id,
        "created_at": datetime.utcnow(),
    }
    return state


def get_auth_url(session_id: str) -> str:
    """Generate Blackboard OAuth URL for a session."""
    state = create_auth_state(session_id)
    callback = f"{SERVER_URL}/oauth/callback"
    
    return (
        f"{BLACKBOARD_URL}/learn/api/public/v1/oauth2/authorizationcode"
        f"?redirect_uri={callback}"
        f"&response_type=code"
        f"&client_id={BLACKBOARD_APP_KEY}"
        f"&scope=read"
        f"&state={state}"
    )


async def exchange_code(code: str, state: str) -> dict:
    """
    Exchange authorization code for tokens.
    Returns {session_id, access_token, user_id} on success.
    Raises Exception on failure.
    """
    # Validate state
    pending = _pending_auth.pop(state, None)
    if not pending:
        raise ValueError("Invalid or expired state")
    
    # Check state isn't too old (5 min max)
    if datetime.utcnow() - pending["created_at"] > timedelta(minutes=5):
        raise ValueError("Auth session expired")
    
    session_id = pending["session_id"]
    callback = f"{SERVER_URL}/oauth/callback"
    
    # Exchange code for tokens
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{BLACKBOARD_URL}/learn/api/public/v1/oauth2/token",
            auth=(BLACKBOARD_APP_KEY, BLACKBOARD_APP_SECRET),
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": callback,
            },
            timeout=30.0,
        )
        
        if resp.status_code != 200:
            raise ValueError(f"Token exchange failed: {resp.text}")
        
        token_data = resp.json()
    
    # Store token for session
    expires_in = token_data.get("expires_in", 3600)
    _session_tokens[session_id] = {
        "access_token": token_data["access_token"],
        "expires_at": datetime.utcnow() + timedelta(seconds=expires_in),
        "blackboard_user_id": token_data.get("user_id"),
    }
    
    return {
        "session_id": session_id,
        "access_token": token_data["access_token"],
        "user_id": token_data.get("user_id"),
    }


# =============================================================================
# FastMCP Server
# =============================================================================

mcp = FastMCP("Blackboard")


@mcp.tool()
async def blackboard_login(ctx: Context) -> str:
    """
    Connect to your Blackboard account.
    
    Opens a login window where you can securely sign in to Blackboard.
    """
    session_id = ctx.session_id
    
    # Already authenticated?
    if is_authenticated(session_id):
        return "✅ You're already connected to Blackboard! Use `blackboard_status` to see details."
    
    # Generate auth URL
    auth_url = get_auth_url(session_id)
    poll_url = f"{SERVER_URL}/oauth/status/{session_id}"
    
    # Return interactive HTML that opens popup and polls for completion
    html = f'''<!DOCTYPE html>
<html>
<head>
<style>
* {{ box-sizing: border-box; font-family: system-ui, sans-serif; }}
body {{ margin: 0; padding: 24px; background: #0f172a; color: white; min-height: 300px; }}
.container {{ max-width: 400px; margin: 0 auto; text-align: center; }}
h2 {{ margin: 0 0 8px; color: #38bdf8; }}
p {{ color: #94a3b8; margin: 0 0 24px; }}
.btn {{ 
    display: inline-block; background: #3b82f6; color: white; 
    padding: 14px 28px; border-radius: 8px; text-decoration: none;
    font-weight: 600; font-size: 16px; border: none; cursor: pointer;
}}
.btn:hover {{ background: #2563eb; }}
.status {{ 
    margin-top: 24px; padding: 16px; border-radius: 8px;
    background: #1e293b; color: #94a3b8;
}}
.status.success {{ background: #065f46; color: #6ee7b7; }}
.status.error {{ background: #7f1d1d; color: #fca5a5; }}
.spinner {{ display: inline-block; width: 16px; height: 16px; 
    border: 2px solid #3b82f6; border-top-color: transparent;
    border-radius: 50%; animation: spin 1s linear infinite; margin-right: 8px; }}
@keyframes spin {{ to {{ transform: rotate(360deg); }} }}
</style>
</head>
<body>
<div class="container">
    <h2>🎓 Connect to Blackboard</h2>
    <p>Sign in to access your courses, grades, and announcements.</p>
    
    <button class="btn" onclick="openLogin()">Sign in with Blackboard</button>
    
    <div id="status" class="status" style="display:none;"></div>
</div>

<script>
let popup = null;
let pollInterval = null;

function openLogin() {{
    // Open popup
    popup = window.open(
        '{auth_url}',
        'blackboard_login',
        'width=500,height=600,menubar=no,toolbar=no'
    );
    
    // Show waiting status
    const status = document.getElementById('status');
    status.style.display = 'block';
    status.className = 'status';
    status.innerHTML = '<span class="spinner"></span> Waiting for you to sign in...';
    
    // Poll for completion
    pollInterval = setInterval(checkStatus, 2000);
}}

async function checkStatus() {{
    try {{
        const resp = await fetch('{poll_url}');
        const data = await resp.json();
        
        if (data.status === 'authenticated') {{
            clearInterval(pollInterval);
            if (popup) popup.close();
            
            const status = document.getElementById('status');
            status.className = 'status success';
            status.innerHTML = '✅ Connected as <strong>' + data.username + '</strong>! You can now use Blackboard tools.';
        }}
    }} catch (e) {{
        // Keep polling
    }}
}}

// Clean up if popup closed manually
setInterval(() => {{
    if (popup && popup.closed && pollInterval) {{
        clearInterval(pollInterval);
        const status = document.getElementById('status');
        if (!status.classList.contains('success')) {{
            status.className = 'status';
            status.innerHTML = 'Login window closed. <a href="#" onclick="openLogin(); return false;">Try again</a>';
        }}
    }}
}}, 1000);
</script>
</body>
</html>'''
    
    return {
        "content": [
            {"type": "text", "text": "👆 Click the button above to connect your Blackboard account."},
            {"type": "resource", "resource": {"uri": "blackboard://login", "mimeType": "text/html", "text": html}}
        ]
    }


@mcp.tool()
async def blackboard_status(ctx: Context) -> str:
    """Check your Blackboard connection status."""
    if is_authenticated(ctx.session_id):
        data = _session_tokens.get(ctx.session_id, {})
        user_id = data.get("blackboard_user_id", "Unknown")
        return f"✅ Connected to Blackboard (User ID: {user_id})"
    return "❌ Not connected. Use `blackboard_login` to connect."


@mcp.tool()
async def blackboard_logout(ctx: Context) -> str:
    """Disconnect from Blackboard."""
    if ctx.session_id in _session_tokens:
        del _session_tokens[ctx.session_id]
    return "✅ Disconnected from Blackboard."


# =============================================================================
# OAuth Callback Routes (added to FastMCP's HTTP server)
# =============================================================================

from starlette.routing import Route
from starlette.responses import HTMLResponse, JSONResponse
import asyncio


async def oauth_callback(request):
    """Handle Blackboard OAuth callback."""
    code = request.query_params.get("code")
    state = request.query_params.get("state")
    error = request.query_params.get("error")
    
    if error:
        return HTMLResponse(f'''
            <html><body style="font-family:system-ui;background:#0f172a;color:white;
                display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;">
                <div style="text-align:center;max-width:400px;">
                    <h2 style="color:#f87171;">❌ Authorization Failed</h2>
                    <p>{error}</p>
                    <p style="color:#64748b;">You can close this window and try again.</p>
                </div>
            </body></html>
        ''', status_code=400)
    
    if not code or not state:
        return HTMLResponse("Missing code or state", status_code=400)
    
    try:
        result = await exchange_code(code, state)
        
        return HTMLResponse(f'''
            <html><body style="font-family:system-ui;background:#0f172a;color:white;
                display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;">
                <div style="text-align:center;max-width:400px;">
                    <h2 style="color:#4ade80;">✅ Connected!</h2>
                    <p>You're now connected to Blackboard.</p>
                    <p style="color:#64748b;">This window will close automatically...</p>
                </div>
            </body></html>
            <script>setTimeout(() => window.close(), 1500);</script>
        ''')
    except Exception as e:
        return HTMLResponse(f'''
            <html><body style="font-family:system-ui;background:#0f172a;color:white;
                display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;">
                <div style="text-align:center;max-width:400px;">
                    <h2 style="color:#f87171;">❌ Error</h2>
                    <p>{str(e)}</p>
                    <p style="color:#64748b;">Please close this window and try again.</p>
                </div>
            </body></html>
        ''', status_code=400)


async def oauth_status(request):
    """Poll endpoint for auth status."""
    session_id = request.path_params.get("session_id")
    
    if is_authenticated(session_id):
        data = _session_tokens.get(session_id, {})
        return JSONResponse({
            "status": "authenticated",
            "username": data.get("blackboard_user_id", "Unknown"),
        })
    
    return JSONResponse({"status": "pending"})


# Add routes to FastMCP
mcp._extra_routes = [
    Route("/oauth/callback", oauth_callback, methods=["GET"]),
    Route("/oauth/status/{session_id}", oauth_status, methods=["GET"]),
]


# =============================================================================
# FastMCP Cloud Entry Point
# =============================================================================
# FastMCP Cloud imports this module and uses the `mcp` instance directly.
# Entry point configuration: server:mcp

"""
Blackboard MCP Server with Two-Stage Authentication

Stage 1: FastMCP Cloud SSO (automatic - protects the server)
Stage 2: Blackboard OAuth (per-session)
"""
import os
import secrets
import httpx
import jwt
from datetime import datetime, timedelta
from fastmcp import FastMCP, Context
from starlette.routing import Route
from starlette.responses import HTMLResponse, JSONResponse

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

# Maps user_id -> {sso_user_id, sso_email, sso_name, session_ids[], first_seen, last_seen, raw_claims}
# Falls back to session_id as key if no stable user_id is available
_sso_identities: dict[str, dict] = {}

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


def extract_jwt_claims(ctx: Context) -> dict:
    """Extract user claims from JWT token in request headers."""
    try:
        # Try to get the Authorization header from the request
        from fastmcp.server.context import request_ctx
        
        request_context = request_ctx.get()
        if not request_context or not hasattr(request_context, 'request'):
            return {}
        
        auth_header = request_context.request.headers.get("authorization", "")
        if not auth_header.startswith("Bearer "):
            return {}
        
        token = auth_header.split(" ")[1]
        
        # Decode JWT without verification (since FastMCP Cloud already verified it)
        import jwt
        claims = jwt.decode(token, options={"verify_signature": False})
        return claims
        
    except Exception as e:
        print(f"Error extracting JWT claims: {e}")
        return {}


def track_sso_identity(ctx: Context) -> dict:
    """
    Track SSO user identity from JWT token.
    Returns the extracted claims for immediate use.
    """
    session_id = ctx.session_id
    
    # Extract claims from JWT
    claims = extract_jwt_claims(ctx)
    
    # Common JWT claim fields
    sso_user_id = claims.get("sub") or claims.get("user_id") or claims.get("uid")
    sso_email = claims.get("email")
    sso_name = claims.get("name")
    
    # Store identity keyed by a stable identifier if available, otherwise use session_id
    # Use the user_id from JWT as the stable key
    storage_key = sso_user_id if sso_user_id else session_id
    
    if storage_key not in _sso_identities:
        _sso_identities[storage_key] = {
            "sso_user_id": sso_user_id,
            "sso_email": sso_email,
            "sso_name": sso_name,
            "session_ids": [session_id],
            "first_seen": datetime.utcnow(),
            "last_seen": datetime.utcnow(),
            "raw_claims": claims,
        }
    else:
        # Update last seen and add session_id if new
        _sso_identities[storage_key]["last_seen"] = datetime.utcnow()
        if session_id not in _sso_identities[storage_key]["session_ids"]:
            _sso_identities[storage_key]["session_ids"].append(session_id)
    
    return claims


# =============================================================================
# FastMCP Server
# =============================================================================

mcp = FastMCP("Blackboard")


@mcp.tool()
async def whoami(ctx: Context) -> str:
    """
    Show your identity and authentication status.
    
    Displays:
    - Your SSO identity (from FastMCP Cloud)
    - Your session ID
    - Your Blackboard connection status
    """
    claims = track_sso_identity(ctx)
    
    session_id = ctx.session_id
    
    # Find the user's identity record (may be keyed by user_id or session_id)
    sso_user_id = claims.get("sub") or claims.get("user_id") or claims.get("uid")
    storage_key = sso_user_id if sso_user_id else session_id
    sso_info = _sso_identities.get(storage_key, {})
    
    # Build identity report
    lines = ["🔍 **Your Identity**\n"]
    
    # SSO Identity (Stage 1 Auth)
    lines.append("**FastMCP Cloud SSO:**")
    if sso_info.get("sso_user_id"):
        lines.append(f"  • User ID: {sso_info['sso_user_id']}")
    if sso_info.get("sso_email"):
        lines.append(f"  • Email: {sso_info['sso_email']}")
    if sso_info.get("sso_name"):
        lines.append(f"  • Name: {sso_info['sso_name']}")
    if not sso_info.get("sso_user_id") and not sso_info.get("sso_email"):
        lines.append("  • No SSO identity found")
        lines.append("  • (This might mean JWT extraction failed)")
    
    # Session Info
    lines.append(f"\n**Session:**")
    lines.append(f"  • Current Session ID: {session_id}")
    if sso_info.get("session_ids") and len(sso_info["session_ids"]) > 1:
        lines.append(f"  • Total sessions for this user: {len(sso_info['session_ids'])}")
        lines.append(f"  • Note: Session IDs may change between requests")
    if sso_info.get("first_seen"):
        lines.append(f"  • First seen: {sso_info['first_seen'].isoformat()}")
    
    # Show raw JWT claims for debugging
    if claims:
        lines.append(f"\n**JWT Claims (for debugging):**")
        for key, value in sorted(claims.items()):
            if key not in ["exp", "iat", "nbf"]:  # Skip timestamps for clarity
                lines.append(f"  • {key}: {value}")
    
    # Blackboard Auth (Stage 2 Auth)
    lines.append(f"\n**Blackboard Connection:**")
    
    # Check if any of the user's sessions have Blackboard auth
    blackboard_connected = False
    bb_user_id = None
    expires_at = None
    
    if sso_info.get("session_ids"):
        for sid in sso_info["session_ids"]:
            if is_authenticated(sid):
                blackboard_connected = True
                bb_data = _session_tokens.get(sid, {})
                bb_user_id = bb_data.get("blackboard_user_id", "Unknown")
                expires_at = bb_data.get("expires_at")
                break
    
    if blackboard_connected:
        lines.append(f"  • Status: ✅ Connected")
        lines.append(f"  • Blackboard User ID: {bb_user_id}")
        if expires_at:
            lines.append(f"  • Token expires: {expires_at.isoformat()}")
    else:
        lines.append(f"  • Status: ❌ Not connected")
        lines.append(f"  • Use `blackboard_login` to connect")
    
    return "\n".join(lines)


@mcp.tool()
async def blackboard_login(ctx: Context) -> str:
    """
    Connect to your Blackboard account.
    
    Returns a link to sign in to Blackboard. After signing in,
    come back here and your tools will work.
    """
    track_sso_identity(ctx)
    session_id = ctx.session_id
    
    # Already authenticated?
    if is_authenticated(session_id):
        return "✅ You're already connected to Blackboard!"
    
    # Generate auth URL
    auth_url = get_auth_url(session_id)
    
    return f"""🔐 **Connect to Blackboard**

Click this link to sign in:
{auth_url}

After you authorize access, come back here and you'll be connected!"""


@mcp.tool()
async def blackboard_status(ctx: Context) -> str:
    """Check your Blackboard connection status."""
    track_sso_identity(ctx)
    
    if is_authenticated(ctx.session_id):
        data = _session_tokens.get(ctx.session_id, {})
        user_id = data.get("blackboard_user_id", "Unknown")
        return f"✅ Connected to Blackboard (User ID: {user_id})"
    return "❌ Not connected. Use `blackboard_login` to connect."


@mcp.tool()
async def blackboard_logout(ctx: Context) -> str:
    """Disconnect from Blackboard."""
    track_sso_identity(ctx)
    
    if ctx.session_id in _session_tokens:
        del _session_tokens[ctx.session_id]
    return "✅ Disconnected from Blackboard."


# =============================================================================
# OAuth Callback Route
# =============================================================================

async def oauth_callback(request):
    """Handle Blackboard OAuth callback."""
    code = request.query_params.get("code")
    state = request.query_params.get("state")
    error = request.query_params.get("error")
    
    if error:
        return HTMLResponse(f"""
<!DOCTYPE html>
<html>
<head>
    <title>Authorization Failed</title>
    <style>
        body {{ font-family: system-ui, sans-serif; background: #0f172a; color: white;
               display: flex; align-items: center; justify-content: center; 
               min-height: 100vh; margin: 0; }}
        .box {{ text-align: center; max-width: 400px; padding: 40px; }}
        h1 {{ color: #f87171; }}
        p {{ color: #94a3b8; }}
    </style>
</head>
<body>
    <div class="box">
        <h1>❌ Authorization Failed</h1>
        <p>{error}</p>
        <p>You can close this window and try again in Claude.</p>
    </div>
</body>
</html>
        """, status_code=400)
    
    if not code or not state:
        return HTMLResponse("Missing code or state", status_code=400)
    
    try:
        result = await exchange_code(code, state)
        
        return HTMLResponse("""
<!DOCTYPE html>
<html>
<head>
    <title>Connected!</title>
    <style>
        body { font-family: system-ui, sans-serif; background: #0f172a; color: white;
               display: flex; align-items: center; justify-content: center; 
               min-height: 100vh; margin: 0; }
        .box { text-align: center; max-width: 400px; padding: 40px; }
        h1 { color: #4ade80; }
        p { color: #94a3b8; }
    </style>
</head>
<body>
    <div class="box">
        <h1>✅ Connected to Blackboard!</h1>
        <p>You can close this window and return to Claude.</p>
        <p>Your Blackboard tools are now ready to use.</p>
    </div>
</body>
</html>
        """)
        
    except Exception as e:
        return HTMLResponse(f"""
<!DOCTYPE html>
<html>
<head>
    <title>Error</title>
    <style>
        body {{ font-family: system-ui, sans-serif; background: #0f172a; color: white;
               display: flex; align-items: center; justify-content: center; 
               min-height: 100vh; margin: 0; }}
        .box {{ text-align: center; max-width: 400px; padding: 40px; }}
        h1 {{ color: #f87171; }}
        p {{ color: #94a3b8; }}
    </style>
</head>
<body>
    <div class="box">
        <h1>❌ Error</h1>
        <p>{str(e)}</p>
        <p>Please close this window and try again.</p>
    </div>
</body>
</html>
        """, status_code=400)


# Add OAuth route to FastMCP
mcp._extra_routes = [
    Route("/oauth/callback", oauth_callback, methods=["GET"]),
]

# =============================================================================
# FastMCP Cloud Entry Point
# =============================================================================
# Entry point: server:mcp

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

# Maps sso_user_id -> {access_token, expires_at, blackboard_user_id, refresh_token (optional)}
# Blackboard tokens are now linked to SSO user identity, not session
_blackboard_tokens: dict[str, dict] = {}

# Maps auth_state -> {sso_user_id, created_at} for pending OAuth flows
_pending_auth: dict[str, dict] = {}

# Maps user_id -> {sso_user_id, sso_email, sso_name, session_ids[], first_seen, last_seen, raw_claims}
# Falls back to session_id as key if no stable user_id is available
_sso_identities: dict[str, dict] = {}

# =============================================================================
# Auth Helpers
# =============================================================================

def get_blackboard_token(sso_user_id: str) -> str | None:
    """Get Blackboard access token for an SSO user, if valid."""
    data = _blackboard_tokens.get(sso_user_id)
    if not data:
        return None
    
    # Check expiration
    if datetime.utcnow() >= data["expires_at"]:
        del _blackboard_tokens[sso_user_id]
        return None
    
    return data["access_token"]


def is_blackboard_authenticated(sso_user_id: str) -> bool:
    """Check if SSO user has valid Blackboard auth."""
    return get_blackboard_token(sso_user_id) is not None


def get_sso_user_id_from_context(ctx: Context) -> str | None:
    """Extract the stable SSO user ID from context."""
    claims = extract_jwt_claims(ctx)
    return claims.get("sub") or claims.get("user_id") or claims.get("uid")


async def make_blackboard_api_call(
    sso_user_id: str,
    endpoint: str,
    method: str = "GET",
    data: dict | None = None,
) -> dict:
    """
    Make an authenticated API call to Blackboard.
    
    Args:
        sso_user_id: The SSO user ID (from JWT)
        endpoint: API endpoint (e.g., "/learn/api/public/v1/courses")
        method: HTTP method (GET, POST, PUT, DELETE)
        data: Optional request body for POST/PUT
    
    Returns:
        Response JSON
    
    Raises:
        ValueError: If user is not authenticated to Blackboard
        httpx.HTTPError: If the API call fails
    """
    access_token = get_blackboard_token(sso_user_id)
    if not access_token:
        raise ValueError("Not authenticated to Blackboard. Please use blackboard_login first.")
    
    url = f"{BLACKBOARD_URL}{endpoint}"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    
    async with httpx.AsyncClient() as client:
        if method == "GET":
            resp = await client.get(url, headers=headers, timeout=30.0)
        elif method == "POST":
            resp = await client.post(url, headers=headers, json=data, timeout=30.0)
        elif method == "PUT":
            resp = await client.put(url, headers=headers, json=data, timeout=30.0)
        elif method == "DELETE":
            resp = await client.delete(url, headers=headers, timeout=30.0)
        else:
            raise ValueError(f"Unsupported HTTP method: {method}")
        
        resp.raise_for_status()
        return resp.json() if resp.text else {}


def create_auth_state(sso_user_id: str) -> str:
    """Create a state token for OAuth flow, linked to SSO user."""
    state = secrets.token_urlsafe(32)
    _pending_auth[state] = {
        "sso_user_id": sso_user_id,
        "created_at": datetime.utcnow(),
    }
    return state


def get_auth_url(sso_user_id: str) -> str:
    """Generate Blackboard OAuth URL for an SSO user."""
    state = create_auth_state(sso_user_id)
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
    Returns {sso_user_id, blackboard_user_id} on success (NO ACCESS TOKEN).
    Raises Exception on failure.
    """
    # Validate state
    pending = _pending_auth.pop(state, None)
    if not pending:
        raise ValueError("Invalid or expired state")
    
    # Check state isn't too old (5 min max)
    if datetime.utcnow() - pending["created_at"] > timedelta(minutes=5):
        raise ValueError("Auth session expired")
    
    sso_user_id = pending["sso_user_id"]
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
    
    # Store token linked to SSO user (NOT session)
    expires_in = token_data.get("expires_in", 3600)
    _blackboard_tokens[sso_user_id] = {
        "access_token": token_data["access_token"],
        "expires_at": datetime.utcnow() + timedelta(seconds=expires_in),
        "blackboard_user_id": token_data.get("user_id"),
        # Optionally store refresh token if Blackboard provides one
        "refresh_token": token_data.get("refresh_token"),
    }
    
    # IMPORTANT: Never return the access token to the user
    return {
        "sso_user_id": sso_user_id,
        "blackboard_user_id": token_data.get("user_id"),
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
    
    NOTE: Blackboard access tokens are NEVER shown to users.
    """
    claims = track_sso_identity(ctx)
    
    session_id = ctx.session_id
    sso_user_id = get_sso_user_id_from_context(ctx)
    
    # Find the user's identity record
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
        lines.append(f"  • Total sessions: {len(sso_info['session_ids'])}")
        lines.append(f"  • Note: Session IDs may change between requests")
    if sso_info.get("first_seen"):
        lines.append(f"  • First seen: {sso_info['first_seen'].isoformat()}")
    
    # Blackboard Auth (Stage 2 Auth)
    lines.append(f"\n**Blackboard Connection:**")
    
    if sso_user_id and is_blackboard_authenticated(sso_user_id):
        bb_data = _blackboard_tokens.get(sso_user_id, {})
        bb_user_id = bb_data.get("blackboard_user_id", "Unknown")
        expires_at = bb_data.get("expires_at")
        lines.append(f"  • Status: ✅ Connected")
        lines.append(f"  • Blackboard User ID: {bb_user_id}")
        if expires_at:
            lines.append(f"  • Token expires: {expires_at.isoformat()}")
        lines.append(f"  • 🔒 Access token secured (never exposed to user)")
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
    sso_user_id = get_sso_user_id_from_context(ctx)
    
    if not sso_user_id:
        return "❌ Unable to identify SSO user. Please try again."
    
    # Already authenticated?
    if is_blackboard_authenticated(sso_user_id):
        return "✅ You're already connected to Blackboard!"
    
    # Generate auth URL
    auth_url = get_auth_url(sso_user_id)
    
    return f"""🔐 **Connect to Blackboard**

Click this link to sign in:
{auth_url}

After you authorize access, come back here and you'll be connected!

Note: Your Blackboard credentials will be securely stored and linked to your SSO identity ({sso_user_id})."""


@mcp.tool()
async def blackboard_status(ctx: Context) -> str:
    """Check your Blackboard connection status."""
    track_sso_identity(ctx)
    sso_user_id = get_sso_user_id_from_context(ctx)
    
    if not sso_user_id:
        return "❌ Unable to identify SSO user."
    
    if is_blackboard_authenticated(sso_user_id):
        data = _blackboard_tokens.get(sso_user_id, {})
        bb_user_id = data.get("blackboard_user_id", "Unknown")
        return f"✅ Connected to Blackboard (User ID: {bb_user_id})\n🔒 Access token secured"
    return "❌ Not connected. Use `blackboard_login` to connect."


@mcp.tool()
async def blackboard_logout(ctx: Context) -> str:
    """Disconnect from Blackboard."""
    track_sso_identity(ctx)
    sso_user_id = get_sso_user_id_from_context(ctx)
    
    if not sso_user_id:
        return "❌ Unable to identify SSO user."
    
    if sso_user_id in _blackboard_tokens:
        del _blackboard_tokens[sso_user_id]
        return "✅ Disconnected from Blackboard. Your access token has been securely removed."
    return "ℹ️ You weren't connected to Blackboard."


@mcp.tool()
async def get_blackboard_courses(ctx: Context) -> str:
    """
    Get a list of your Blackboard courses.
    
    This is an example tool that demonstrates how to make authenticated
    Blackboard API calls without exposing access tokens.
    """
    track_sso_identity(ctx)
    sso_user_id = get_sso_user_id_from_context(ctx)
    
    if not sso_user_id:
        return "❌ Unable to identify SSO user."
    
    try:
        # Make authenticated API call (token handled internally)
        courses = await make_blackboard_api_call(
            sso_user_id,
            "/learn/api/public/v1/courses",
            method="GET"
        )
        
        # Format response
        if not courses or "results" not in courses:
            return "No courses found."
        
        lines = ["📚 **Your Blackboard Courses**\n"]
        for course in courses["results"][:10]:  # Limit to 10 courses
            course_id = course.get("id", "Unknown")
            course_name = course.get("name", "Unnamed Course")
            lines.append(f"  • {course_name} (ID: {course_id})")
        
        if len(courses["results"]) > 10:
            lines.append(f"\n... and {len(courses['results']) - 10} more courses")
        
        return "\n".join(lines)
        
    except ValueError as e:
        return f"❌ {str(e)}"
    except Exception as e:
        return f"❌ Error fetching courses: {str(e)}"


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

import os
from fastmcp import FastMCP, Context
from fastmcp.server.dependencies import get_http_request
from dotenv import load_dotenv
from auth import token_manager
from blackboard_client import BlackboardClient

load_dotenv()

mcp = FastMCP("Blackboard")

def get_session_id(ctx: Context) -> str:
    """
    Get the MCP session ID from either:
    1. Context (if available)
    2. Request state (from our middleware)
    """
    # Try FastMCP context first
    if ctx and ctx.session_id:
        return ctx.session_id
    
    # Fall back to request state
    try:
        request = get_http_request()
        if hasattr(request.state, 'mcp_session_id') and request.state.mcp_session_id:
            return request.state.mcp_session_id
    except:
        pass
    
    return None

@mcp.tool()
async def get_auth_link(ctx: Context) -> str:
    """Get authentication link for Blackboard"""
    
    session_id = get_session_id(ctx)
    print(f"🔍 get_auth_link - Session: {session_id[:16] if session_id else 'None'}...")
    
    auth_session_id = token_manager.create_auth_session()
    server_url = os.getenv("SERVER_URL", "https://blackboard-auth-demo.fastmcp.app")
    auth_url = f"{server_url}/auth/start?session={auth_session_id}"
    
    return f"""🔐 **Blackboard Authentication**

1. Click this link: {auth_url}
2. Log in with your Blackboard credentials
3. Copy the code from the success page
4. Return here and use: complete_auth("<code>")

Debug - MCP Session: {session_id[:16] if session_id else 'None'}..."""

@mcp.tool()
async def complete_auth(auth_code: str, ctx: Context) -> str:
    """Complete Blackboard authentication"""
    
    session_id = get_session_id(ctx)
    print(f"🔍 complete_auth - Session: {session_id[:16] if session_id else 'None'}...")
    
    if not session_id:
        return "❌ Error: No MCP session ID available"
    
    success = await token_manager.link_to_mcp_session(auth_code, session_id)
    
    if success:
        return f"""✅ **Authentication Complete!**

Session: {session_id[:16]}...
You can now use get_my_courses()"""
    else:
        return "❌ Invalid or expired code"

@mcp.tool()
async def get_my_courses(ctx: Context) -> str:
    """Get your Blackboard courses"""
    
    session_id = get_session_id(ctx)
    print(f"🔍 get_my_courses - Session: {session_id[:16] if session_id else 'None'}...")
    
    if not session_id:
        return "❌ No session ID"
    
    bb_token = await token_manager.get_token(session_id)
    
    if not bb_token:
        return "⚠️ Not authenticated. Use get_auth_link() first."
    
    try:
        client = BlackboardClient(
            base_url=os.getenv("BLACKBOARD_URL"),
            app_key=os.getenv("BLACKBOARD_APP_KEY"),
            app_secret=os.getenv("BLACKBOARD_APP_SECRET")
        )
        
        courses = await client.get_courses(bb_token["access_token"])
        
        result = f"📚 **Your Courses** (Session: {session_id[:16]}...)\n\n"
        
        if not courses:
            return result + "No courses found."
        
        for course in courses:
            result += f"• {course.get('name', 'Unknown')}\n"
        
        return result
        
    except Exception as e:
        return f"❌ Error: {str(e)}"

@mcp.tool()
async def debug_session(ctx: Context) -> str:
    """Check current session info"""
    
    session_id = get_session_id(ctx)
    has_token = await token_manager.get_token(session_id) if session_id else None
    
    # Try to get from both sources
    ctx_session = ctx.session_id if ctx else None
    
    try:
        request = get_http_request()
        state_session = getattr(request.state, 'mcp_session_id', None)
    except:
        state_session = None
    
    return f"""🔍 **Debug Info**

Context Session: {ctx_session[:16] if ctx_session else 'None'}...
State Session: {state_session[:16] if state_session else 'None'}...
Final Session: {session_id[:16] if session_id else 'None'}...
Has Token: {has_token is not None}
Active Tokens: {token_manager.get_session_count()}
Pending Auths: {token_manager.get_pending_auth_count()}"""

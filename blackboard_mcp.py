import os
from fastmcp import FastMCP, Context
from dotenv import load_dotenv
from auth import token_manager
from blackboard_client import BlackboardClient

load_dotenv()

mcp = FastMCP("Blackboard")

@mcp.tool()
async def get_auth_link(ctx: Context) -> str:
    """Get authentication link for Blackboard"""
    auth_session_id = token_manager.create_auth_session()
    server_url = os.getenv("SERVER_URL")
    auth_url = f"{server_url}/auth/start?session={auth_session_id}"
    
    return f"""🔐 **Blackboard Authentication**

1. Click this link: {auth_url}
2. Log in with your Blackboard credentials
3. Copy the code from the success page
4. Return here and use: complete_auth("<paste code>")"""

@mcp.tool()
async def complete_auth(auth_code: str, ctx: Context) -> str:
    """Complete authentication with code from browser"""
    mcp_session_id = ctx.session_id
    
    if not mcp_session_id:
        return "❌ Error: No MCP session ID available"
    
    success = await token_manager.link_to_mcp_session(auth_code, mcp_session_id)
    
    if success:
        return f"✅ Authentication complete! Session: {mcp_session_id[:16]}..."
    else:
        return "❌ Invalid or expired code. Try get_auth_link() again."

@mcp.tool()
async def get_courses(ctx: Context) -> str:
    """Get your Blackboard courses"""
    mcp_session_id = ctx.session_id
    
    if not mcp_session_id:
        return "❌ No session ID"
    
    bb_token = await token_manager.get_token(mcp_session_id)
    
    if not bb_token:
        return "⚠️ Not authenticated. Use get_auth_link() first."
    
    try:
        client = BlackboardClient(
            base_url=os.getenv("BLACKBOARD_URL"),
            app_key=os.getenv("BLACKBOARD_APP_KEY"),
            app_secret=os.getenv("BLACKBOARD_APP_SECRET")
        )
        
        courses = await client.get_courses(bb_token["access_token"])
        
        result = f"📚 **Your Courses**\n\n"
        for course in courses:
            result += f"• {course.get('name', 'Unknown')}\n"
        
        return result
        
    except Exception as e:
        return f"❌ Error: {str(e)}"

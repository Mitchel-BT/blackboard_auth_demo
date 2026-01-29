"""
Blackboard MCP Tools with multi-tenant user identity
"""
import os
from fastmcp import FastMCP, Context
from fastmcp.server.dependencies import get_token_claims
from dotenv import load_dotenv
from blackboard_client import BlackboardClient
from auth import auth
import logging

load_dotenv()
logger = logging.getLogger(__name__)

# Create FastMCP with OAuth
mcp = FastMCP("Blackboard", auth=auth)

def get_user_id(ctx: Context) -> str:
    """
    Get the stable user identifier from OAuth claims.
    This is the Blackboard user ID and persists across all sessions.
    """
    try:
        claims = get_token_claims()
        user_id = claims.get("sub")
        
        if not user_id:
            raise ValueError("No user ID found in token claims")
        
        logger.info(f"User ID from claims: {user_id}")
        return user_id
    except Exception as e:
        logger.warning(f"Could not get user ID from claims: {e}")
        # Fallback to session_id if needed
        return ctx.session_id if ctx and ctx.session_id else "unknown"

@mcp.tool()
async def get_my_courses(ctx: Context, access_token: str) -> str:
    """
    Get all your enrolled Blackboard courses.
    Authentication happens automatically when you connect this server in Claude.
    """
    user_id = get_user_id(ctx)
    logger.info(f"get_my_courses called by user: {user_id}")
    
    try:
        client = BlackboardClient(
            base_url=os.getenv("BLACKBOARD_URL"),
            app_key=os.getenv("BLACKBOARD_APP_KEY"),
            app_secret=os.getenv("BLACKBOARD_APP_SECRET")
        )
        
        courses = await client.get_courses(access_token)
        
        result = f"📚 **Your Courses**\n\n"
        
        if not courses:
            return result + "No courses found."
        
        for course in courses:
            result += f"• {course.get('name', 'Unknown')} ({course.get('courseId', 'N/A')})\n"
        
        return result
        
    except Exception as e:
        logger.error(f"Error getting courses: {e}")
        return f"❌ Error fetching courses: {str(e)}"

@mcp.tool()
async def get_my_grades(course_id: str, ctx: Context, access_token: str) -> str:
    """
    Get your grades for a specific course.
    
    Args:
        course_id: The Blackboard course ID
    """
    user_id = get_user_id(ctx)
    logger.info(f"get_my_grades called by user: {user_id} for course: {course_id}")
    
    try:
        client = BlackboardClient(
            base_url=os.getenv("BLACKBOARD_URL"),
            app_key=os.getenv("BLACKBOARD_APP_KEY"),
            app_secret=os.getenv("BLACKBOARD_APP_SECRET")
        )
        
        grades = await client.get_my_grades(course_id, access_token)
        
        result = f"📊 **Grades for {course_id}**\n\n"
        
        if not grades:
            return result + "No grades found."
        
        for grade in grades:
            result += f"• {grade.get('name', 'Unknown')}: {grade.get('score', 'N/A')}\n"
        
        return result
        
    except Exception as e:
        logger.error(f"Error getting grades: {e}")
        return f"❌ Error fetching grades: {str(e)}"

@mcp.tool()
async def get_course_announcements(course_id: str, ctx: Context, access_token: str) -> str:
    """
    Get announcements for a specific course.
    
    Args:
        course_id: The Blackboard course ID
    """
    user_id = get_user_id(ctx)
    logger.info(f"get_course_announcements called by user: {user_id}")
    
    try:
        client = BlackboardClient(
            base_url=os.getenv("BLACKBOARD_URL"),
            app_key=os.getenv("BLACKBOARD_APP_KEY"),
            app_secret=os.getenv("BLACKBOARD_APP_SECRET")
        )
        
        announcements = await client.get_course_announcements(course_id, access_token)
        
        result = f"📢 **Announcements for {course_id}**\n\n"
        
        if not announcements:
            return result + "No announcements."
        
        for announcement in announcements:
            title = announcement.get('title', 'Untitled')
            body = announcement.get('body', '')[:200]
            result += f"• **{title}**\n  {body}...\n\n"
        
        return result
        
    except Exception as e:
        logger.error(f"Error getting announcements: {e}")
        return f"❌ Error fetching announcements: {str(e)}"

@mcp.tool()
async def debug_identity(ctx: Context, access_token: str) -> str:
    """
    Debug authentication and identity information.
    Shows the stable user ID used for multi-tenancy.
    """
    user_id = get_user_id(ctx)
    session_id = ctx.session_id if ctx else None
    
    # Get all OAuth claims
    try:
        claims = get_token_claims()
        claims_list = [f"  {k}: {v}" for k, v in claims.items()]
        claims_info = "\n".join(claims_list)
    except Exception as e:
        claims_info = f"  Error getting claims: {e}"
    
    return f"""🔍 **Identity & Authentication Debug**

MULTI-TENANT USER IDENTIFIER (stable across sessions):
  Blackboard User ID: {user_id}
  
MCP SESSION (may change between conversations):
  Session ID: {session_id[:16] if session_id else 'None'}...
  
OAUTH CLAIMS (from token verification):
{claims_info}

ACCESS TOKEN:
  Has Token: {bool(access_token)}
  Token Preview: {access_token[:8] if access_token else 'None'}...***

💡 The Blackboard User ID is your stable identifier.
   It persists across all Claude sessions and devices."""

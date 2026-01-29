"""
Blackboard MCP Tools with multi-tenant user identity (ChatGPT-friendly)

Key changes vs original:
- DO NOT accept `access_token` as a tool parameter (ChatGPT may hide these tools).
- Pull the access token from FastMCP auth via get_access_token().
- NO mcp.enable(...) (your FastMCP version doesn't have it).
"""

import os
import logging
from dotenv import load_dotenv

from fastmcp import FastMCP, Context
from fastmcp.server.dependencies import get_access_token

from blackboard_client import BlackboardClient
from auth import auth

load_dotenv()
logger = logging.getLogger(__name__)

# Create FastMCP with OAuth
mcp = FastMCP("Blackboard", auth=auth)


def _get_oauth_access_token_str() -> str:
    """
    Extract an OAuth access token string from FastMCP's get_access_token().

    FastMCP versions differ in attribute naming, so try several common forms.
    """
    token_obj = get_access_token()

    # Common attribute names across versions
    for attr in ("token", "access_token", "value"):
        val = getattr(token_obj, attr, None)
        if isinstance(val, str) and val:
            return val

    # Some versions may return a dict-like object
    try:
        val = token_obj.get("access_token")  # type: ignore[attr-defined]
        if isinstance(val, str) and val:
            return val
    except Exception:
        pass

    raise RuntimeError(
        "Could not extract access token string from get_access_token(). "
        "Inspect the AccessToken object to determine the correct attribute."
    )


def get_user_id(ctx: Context) -> str:
    """
    Get the stable user identifier from OAuth token claims.
    Uses get_access_token() which returns an object with .claims on most versions.
    """
    try:
        token = get_access_token()
        claims = getattr(token, "claims", {}) or {}
        user_id = claims.get("sub")

        if user_id:
            logger.info("User ID from token claims: %s", user_id)
            return user_id

        logger.warning("No 'sub' claim found in token claims")
        return ctx.session_id if ctx and getattr(ctx, "session_id", None) else "unknown"

    except Exception as e:
        logger.error("Error getting user ID from token: %s", e)
        return ctx.session_id if ctx and getattr(ctx, "session_id", None) else "unknown"


def _client() -> BlackboardClient:
    return BlackboardClient(
        base_url=os.getenv("BLACKBOARD_URL"),
        app_key=os.getenv("BLACKBOARD_APP_KEY"),
        app_secret=os.getenv("BLACKBOARD_APP_SECRET"),
    )


@mcp.tool()
async def get_my_courses(ctx: Context) -> str:
    """
    Get all your enrolled Blackboard courses.
    Authentication happens via the connected OAuth session.
    """
    user_id = get_user_id(ctx)
    logger.info("get_my_courses called by user: %s", user_id)

    try:
        access_token = _get_oauth_access_token_str()
        courses = await _client().get_courses(access_token)

        result = "📚 **Your Courses**\n\n"
        if not courses:
            return result + "No courses found."

        for course in courses:
            result += f"• {course.get('name', 'Unknown')} ({course.get('courseId', 'N/A')})\n"

        return result

    except Exception as e:
        logger.error("Error getting courses: %s", e)
        return f"❌ Error fetching courses: {str(e)}"


@mcp.tool()
async def get_my_grades(ctx: Context, course_id: str) -> str:
    """
    Get your grades for a specific course.

    Args:
        course_id: The Blackboard course ID
    """
    user_id = get_user_id(ctx)
    logger.info("get_my_grades called by user: %s for course: %s", user_id, course_id)

    try:
        access_token = _get_oauth_access_token_str()
        grades = await _client().get_my_grades(course_id, access_token)

        result = f"📊 **Grades for {course_id}**\n\n"
        if not grades:
            return result + "No grades found."

        for grade in grades:
            result += f"• {grade.get('name', 'Unknown')}: {grade.get('score', 'N/A')}\n"

        return result

    except Exception as e:
        logger.error("Error getting grades: %s", e)
        return f"❌ Error fetching grades: {str(e)}"


@mcp.tool()
async def get_course_announcements(ctx: Context, course_id: str) -> str:
    """
    Get announcements for a specific course.

    Args:
        course_id: The Blackboard course ID
    """
    user_id = get_user_id(ctx)
    logger.info("get_course_announcements called by user: %s for course: %s", user_id, course_id)

    try:
        access_token = _get_oauth_access_token_str()
        announcements = await _client().get_course_announcements(course_id, access_token)

        result = f"📢 **Announcements for {course_id}**\n\n"
        if not announcements:
            return result + "No announcements."

        for announcement in announcements:
            title = announcement.get("title", "Untitled")
            body = (announcement.get("body", "") or "")[:200]
            result += f"• **{title}**\n  {body}...\n\n"

        return result

    except Exception as e:
        logger.error("Error getting announcements: %s", e)
        return f"❌ Error fetching announcements: {str(e)}"


@mcp.tool()
async def debug_identity(ctx: Context) -> str:
    """
    Debug authentication and identity information.
    Shows the stable user ID used for multi-tenancy.
    """
    user_id = get_user_id(ctx)
    session_id = getattr(ctx, "session_id", None)

    # Claims
    try:
        token = get_access_token()
        claims = dict(getattr(token, "claims", {}) or {})
        claims_lines = "\n".join([f"  {k}: {v}" for k, v in claims.items()]) or "  (no claims available)"
    except Exception as e:
        claims_lines = f"  Error getting claims: {e}"

    # Token preview
    try:
        access_token = _get_oauth_access_token_str()
        token_preview = f"{access_token[:8]}..."
        has_token = True
    except Exception as e:
        token_preview = f"None... ({e})"
        has_token = False

    return f"""🔍 **Identity & Authentication Debug**

MULTI-TENANT USER IDENTIFIER (stable across sessions):
  Blackboard User ID: {user_id}

MCP SESSION (may change between conversations):
  Session ID: {session_id[:16] if session_id else 'None'}...

OAUTH CLAIMS (from token.claims):
{claims_lines}

ACCESS TOKEN:
  Has Token: {has_token}
  Token Preview: {token_preview}

💡 The Blackboard User ID (from claims['sub']) is your stable identifier.
"""

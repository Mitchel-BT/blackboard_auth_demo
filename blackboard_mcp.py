"""
Blackboard MCP Tools (FastMCP Cloud + Claude + ChatGPT)

Behavior:
- Tools are always visible (tools/list allowed without auth).
- Using tools requires login (tools/call requires a valid token).
- Force OpenAI tool visibility metadata at emission time.
"""

import os
import logging
from dotenv import load_dotenv

from fastmcp import FastMCP, Context
from fastmcp.server.dependencies import get_access_token
from fastmcp.server.middleware import Middleware

from blackboard_client import BlackboardClient
from auth import auth

load_dotenv()
logger = logging.getLogger(__name__)

# OpenAI visibility hint (consumed by ChatGPT MCP integration)
OPENAI_PUBLIC_META = {
    "openai/visibility": "public",
    "openai/widgetAccessible": True,
}

# ✅ IMPORTANT: No AuthMiddleware(require_auth) here.
# That middleware hides tools pre-login. We want tools visible, but calls gated.
mcp = FastMCP("Blackboard", auth=auth)


class ForceOpenAIPublicTools(Middleware):
    """
    Last-mile emission control: ensure tools are visible to OpenAI ChatGPT
    by setting tool.meta keys that become MCP tool descriptor `_meta`.
    """

    async def on_list_tools(self, context, call_next):
        tools = await call_next(context)

        if isinstance(tools, (list, tuple)):
            for t in tools:
                meta = getattr(t, "meta", None)
                if not isinstance(meta, dict):
                    meta = {}
                    setattr(t, "meta", meta)
                meta["openai/visibility"] = "public"
                meta["openai/widgetAccessible"] = True

        return tools


class RequireAuthOnToolCall(Middleware):
    """
    Allow handshake + discovery unauthenticated.
    Require authentication only when a tool is actually called.
    """

    async def on_call_tool(self, context, call_next):
        # When a tool is called, require access token to be present & valid.
        try:
            token_obj = get_access_token()
        except Exception:
            token_obj = None

        if not token_obj:
            # Return a user-facing error. The client should prompt OAuth.
            # (Raising PermissionError typically maps to a tool-call error response.)
            raise PermissionError("Login required. Please connect your Blackboard account and try again.")

        return await call_next(context)


# Register middleware at import time (FastMCP Cloud will import this module)
mcp.add_middleware(ForceOpenAIPublicTools())
mcp.add_middleware(RequireAuthOnToolCall())


def _get_oauth_access_token_str() -> str:
    """
    Extract access token string from FastMCP get_access_token() object.
    """
    token_obj = get_access_token()
    if token_obj is None:
        raise RuntimeError("No access token available (not authenticated).")

    for attr in ("token", "access_token", "value"):
        val = getattr(token_obj, attr, None)
        if isinstance(val, str) and val:
            return val

    try:
        val = token_obj.get("access_token")  # type: ignore[attr-defined]
        if isinstance(val, str) and val:
            return val
    except Exception:
        pass

    raise RuntimeError("Could not extract access token string from get_access_token().")


def get_user_id(ctx: Context) -> str:
    """
    Stable user identifier from token claims where available.
    Falls back to session_id if unauthenticated.
    """
    try:
        token = get_access_token()
        claims = getattr(token, "claims", {}) or {}
        user_id = claims.get("sub")
        if user_id:
            return user_id
    except Exception:
        pass

    return ctx.session_id if ctx and getattr(ctx, "session_id", None) else "unknown"


def _client() -> BlackboardClient:
    return BlackboardClient(
        base_url=os.getenv("BLACKBOARD_URL"),
        app_key=os.getenv("BLACKBOARD_APP_KEY"),
        app_secret=os.getenv("BLACKBOARD_APP_SECRET"),
    )


@mcp.tool(meta=OPENAI_PUBLIC_META, annotations={"readOnlyHint": True})
async def get_my_courses(ctx: Context) -> str:
    """Get all your enrolled Blackboard courses."""
    user_id = get_user_id(ctx)
    logger.info("get_my_courses called by user: %s", user_id)

    access_token = _get_oauth_access_token_str()
    courses = await _client().get_courses(access_token)

    result = "📚 **Your Courses**\n\n"
    if not courses:
        return result + "No courses found."

    for course in courses:
        result += f"• {course.get('name', 'Unknown')} ({course.get('courseId', 'N/A')})\n"

    return result


@mcp.tool(meta=OPENAI_PUBLIC_META, annotations={"readOnlyHint": True})
async def get_my_grades(ctx: Context, course_id: str) -> str:
    """Get your grades for a specific course."""
    user_id = get_user_id(ctx)
    logger.info("get_my_grades called by user: %s for course: %s", user_id, course_id)

    access_token = _get_oauth_access_token_str()
    grades = await _client().get_my_grades(course_id, access_token)

    result = f"📊 **Grades for {course_id}**\n\n"
    if not grades:
        return result + "No grades found."

    for grade in grades:
        result += f"• {grade.get('name', 'Unknown')}: {grade.get('score', 'N/A')}\n"

    return result


@mcp.tool(meta=OPENAI_PUBLIC_META, annotations={"readOnlyHint": True})
async def get_course_announcements(ctx: Context, course_id: str) -> str:
    """Get announcements for a specific course."""
    user_id = get_user_id(ctx)
    logger.info("get_course_announcements called by user: %s for course: %s", user_id, course_id)

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


@mcp.tool(meta=OPENAI_PUBLIC_META, annotations={"readOnlyHint": True})
async def debug_identity(ctx: Context) -> str:
    """Debug authentication and identity information."""
    user_id = get_user_id(ctx)
    session_id = getattr(ctx, "session_id", None)

    try:
        token = get_access_token()
        claims = dict(getattr(token, "claims", {}) or {})
        claims_lines = "\n".join([f"  {k}: {v}" for k, v in claims.items()]) or "  (no claims available)"
    except Exception as e:
        claims_lines = f"  Error getting claims: {e}"

    try:
        access_token = _get_oauth_access_token_str()
        token_preview = f"{access_token[:8]}..."
        has_token = True
    except Exception as e:
        token_preview = f"None... ({e})"
        has_token = False

    return f"""🔍 **Identity & Authentication Debug**

Blackboard User ID (claims['sub']): {user_id}
Session ID: {session_id[:16] if session_id else 'None'}...

OAUTH CLAIMS:
{claims_lines}

ACCESS TOKEN:
  Has Token: {has_token}
  Token Preview: {token_preview}
"""

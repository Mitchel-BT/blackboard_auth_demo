"""
Blackboard MCP Tools (ChatGPT + Claude + FastMCP Cloud)

Key goals:
- Initialize must succeed without requiring a token (no 401 on initialize).
- OAuth is handled by OAuthProxy, but tools require auth to be visible/callable.
- Force OpenAI tool visibility meta at emission time.

FastMCP Cloud entrypoint should be: blackboard_mcp.py:mcp
"""

import os
import logging
from dotenv import load_dotenv

from fastmcp import FastMCP, Context
from fastmcp.server.dependencies import get_access_token
from fastmcp.server.middleware import Middleware, AuthMiddleware
from fastmcp.server.auth import require_auth

from blackboard_client import BlackboardClient
from auth import auth

load_dotenv()
logger = logging.getLogger(__name__)

# OpenAI visibility hint (consumed by ChatGPT MCP integration)
OPENAI_PUBLIC_META = {
    "openai/visibility": "public",
    "openai/widgetAccessible": True,
}

# Create FastMCP server with OAuth proxy AND enforced authorization for tools/resources/prompts.
# AuthMiddleware enforces authorization (blocks execution) and filters list responses. :contentReference[oaicite:3]{index=3}
mcp = FastMCP(
    "Blackboard",
    auth=auth,
    middleware=[
        AuthMiddleware(auth=require_auth),
    ],
)


class ForceOpenAIPublicTools(Middleware):
    """
    Ensure all tools emitted by list_tools have OpenAI visibility set to public.
    This is a last-mile emission control layer.
    """

    async def on_list_tools(self, context, call_next):
        tools = await call_next(context)

        # tools is typically a sequence of Tool objects in FastMCP middleware
        if isinstance(tools, (list, tuple)):
            for t in tools:
                meta = getattr(t, "meta", None)
                if not isinstance(meta, dict):
                    meta = {}
                    setattr(t, "meta", meta)
                meta["openai/visibility"] = "public"
                meta["openai/widgetAccessible"] = True

        return tools


# Add emission-control middleware
mcp.add_middleware(ForceOpenAIPublicTools())


def _get_oauth_access_token_str() -> str:
    """
    Extract an OAuth access token string from FastMCP's get_access_token().
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


# NOTE:
# We keep meta=OPENAI_PUBLIC_META for static declaration and ALSO have middleware forcing it at list time.
# Tools are protected by AuthMiddleware(require_auth) so they will appear only after OAuth. :contentReference[oaicite:4]{index=4}

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

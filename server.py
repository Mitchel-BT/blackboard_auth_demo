"""
Blackboard MCP Server Entry Point
OAuth handled automatically by FastMCP OAuthProxy

This entrypoint wraps the FastMCP ASGI app and forces tools to be "public"
for ChatGPT by injecting `_meta.openai/visibility = "public"` into the
tools/list response.
"""

import os
import json
from typing import Callable, Awaitable, Dict, Any, Optional

from dotenv import load_dotenv
from blackboard_mcp import mcp

load_dotenv()

OPENAI_PUBLIC = {"openai/visibility": "public"}


class ForcePublicToolsASGI:
    """
    ASGI middleware that intercepts JSON responses and, when it detects an MCP
    tools/list payload, injects `_meta.openai/visibility = "public"` onto every tool.

    Safe for Claude and other MCP clients (extra _meta is ignored if not used).
    """

    def __init__(self, app):
        self.app = app

    async def __call__(
        self,
        scope: Dict[str, Any],
        receive: Callable[[], Awaitable[Dict[str, Any]]],
        send: Callable[[Dict[str, Any]], Awaitable[None]],
    ):
        if scope.get("type") != "http":
            return await self.app(scope, receive, send)

        status_code: Optional[int] = None
        headers: Optional[list] = None
        body_parts: list[bytes] = []

        async def send_wrapper(message: Dict[str, Any]):
            nonlocal status_code, headers, body_parts

            if message["type"] == "http.response.start":
                status_code = message.get("status", 200)
                headers = message.get("headers", [])
                # Delay sending until we see the full body (so we can rewrite)
                return

            if message["type"] == "http.response.body":
                body_parts.append(message.get("body", b""))
                if message.get("more_body", False):
                    return  # keep buffering

                full_body = b"".join(body_parts)
                new_body = self._rewrite_if_tools_list(full_body, headers or [])

                # If body changed, fix Content-Length if present
                if new_body != full_body and headers is not None:
                    headers = [
                        (k, v)
                        for (k, v) in headers
                        if k.lower() != b"content-length"
                    ]
                    headers.append((b"content-length", str(len(new_body)).encode("utf-8")))

                await send(
                    {
                        "type": "http.response.start",
                        "status": status_code or 200,
                        "headers": headers or [],
                    }
                )
                await send(
                    {
                        "type": "http.response.body",
                        "body": new_body,
                        "more_body": False,
                    }
                )
                return

            await send(message)

        await self.app(scope, receive, send_wrapper)

    def _rewrite_if_tools_list(self, body: bytes, headers: list) -> bytes:
        # Only touch JSON responses
        content_type = None
        for k, v in headers:
            if k.lower() == b"content-type":
                content_type = v.decode("utf-8", "ignore")
                break
        if content_type and "application/json" not in content_type:
            return body

        try:
            data = json.loads(body.decode("utf-8"))
        except Exception:
            return body

        # Common shapes:
        # - {"result": {"tools": [...]}}
        # - {"tools": [...]}
        tools = None
        if isinstance(data, dict):
            if isinstance(data.get("result"), dict) and isinstance(data["result"].get("tools"), list):
                tools = data["result"]["tools"]
            elif isinstance(data.get("tools"), list):
                tools = data["tools"]

        if not isinstance(tools, list) or not tools:
            return body

        changed = False
        for t in tools:
            if not isinstance(t, dict):
                continue

            meta = t.get("_meta")
            if not isinstance(meta, dict):
                meta = {}
                t["_meta"] = meta

            # Force OpenAI visibility public
            if meta.get("openai/visibility") != "public":
                meta["openai/visibility"] = "public"
                changed = True

        if not changed:
            return body

        return json.dumps(data).encode("utf-8")


if __name__ == "__main__":
    import uvicorn

    # Get ASGI app from FastMCP (includes OAuth routes automatically)
    app = mcp.get_asgi_app()

    # Wrap it to force tool visibility for ChatGPT
    app = ForcePublicToolsASGI(app)

    port = int(os.getenv("PORT", 8000))

    print("")
    print("=" * 60)
    print("🚀 BLACKBOARD MCP SERVER")
    print("=" * 60)
    print(f"Server URL: http://localhost:{port}")
    print(f"MCP Endpoint: http://localhost:{port}/mcp")
    print("OAuth: Handled automatically by FastMCP OAuthProxy")
    print("=" * 60)
    print("")

    uvicorn.run(app, host="0.0.0.0", port=port)

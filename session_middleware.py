"""
Custom middleware to ensure proper MCP session management
"""
import uuid
from typing import Optional
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

class MCPSessionMiddleware(BaseHTTPMiddleware):
    """
    Ensures every MCP request has a consistent session ID
    following the MCP protocol spec
    """
    
    async def dispatch(self, request: Request, call_next):
        # Only apply to MCP endpoint
        if not request.url.path.startswith("/mcp"):
            return await call_next(request)
        
        # Get session ID from header (case-insensitive)
        session_id = (
            request.headers.get("Mcp-Session-Id") or 
            request.headers.get("mcp-session-id")
        )
        
        # If this is an initialize request and no session ID, generate one
        if request.method == "POST":
            try:
                body = await request.body()
                import json
                data = json.loads(body)
                
                # Store body for later use
                request._body = body
                
                if data.get("method") == "initialize" and not session_id:
                    session_id = str(uuid.uuid4())
                    print(f"✨ Generated new MCP session: {session_id[:16]}...")
            except:
                pass
        
        # Store session ID in request state
        request.state.mcp_session_id = session_id
        
        if session_id:
            print(f"📌 MCP Session: {session_id[:16]}...")
        
        # Process request
        response = await call_next(request)
        
        # Add session ID to response headers if this was initialize
        if session_id and hasattr(request, '_body'):
            try:
                import json
                data = json.loads(request._body)
                if data.get("method") == "initialize":
                    response.headers["Mcp-Session-Id"] = session_id
                    print(f"📤 Sent session in header: {session_id[:16]}...")
            except:
                pass
        
        return response

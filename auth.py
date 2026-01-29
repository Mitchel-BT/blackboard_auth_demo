"""
Authentication for Blackboard MCP Server using FastMCP OAuthProxy
Multi-tenant with persistent user identity from OAuth
"""
import os
import httpx
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Configuration
BLACKBOARD_URL = os.environ.get("BLACKBOARD_URL")
BLACKBOARD_APP_KEY = os.environ.get("BLACKBOARD_APP_KEY")
BLACKBOARD_APP_SECRET = os.environ.get("BLACKBOARD_APP_SECRET")
SERVER_URL = os.environ.get("SERVER_URL")

if not all([BLACKBOARD_URL, BLACKBOARD_APP_KEY, BLACKBOARD_APP_SECRET, SERVER_URL]):
    raise EnvironmentError("Missing required environment variables")

from fastmcp.server.auth import OAuthProxy
from fastmcp.server.auth.providers.bearer import TokenVerifier, AccessToken


class BlackboardTokenVerifier(TokenVerifier):
    """
    Verifies Blackboard tokens and extracts user identity.
    The 'sub' claim becomes the stable user identifier for multi-tenancy.
    """
    
    def __init__(self, blackboard_url: str):
        self.blackboard_url = blackboard_url.rstrip("/")
    
    async def verify_token(self, token: str) -> Optional[AccessToken]:
        """
        Verify token by calling Blackboard API and extract user identity.
        Returns AccessToken with user identity claims.
        """
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.blackboard_url}/learn/api/public/v1/users/me",
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=10.0
                )
                
                if response.status_code == 200:
                    user_data = response.json()
                    
                    # Extract Blackboard user ID - this is the stable identifier
                    blackboard_user_id = user_data.get("id")  # e.g., "_12345_1"
                    
                    name_parts = user_data.get("name", {})
                    full_name = f"{name_parts.get('given', '')} {name_parts.get('family', '')}".strip()
                    
                    logger.info(f"✅ Token verified for Blackboard user: {blackboard_user_id}")
                    
                    # Return AccessToken object instead of dict
                    return AccessToken(
                        token=token,
                        client_id=blackboard_user_id,  # PRIMARY USER IDENTIFIER
                        scopes=["read", "write", "offline"],
                        claims={
                            "sub": blackboard_user_id,
                            "name": full_name or user_data.get("userName"),
                            "email": user_data.get("contact", {}).get("email"),
                            "userName": user_data.get("userName"),
                        }
                    )
                
                logger.warning(f"Token verification failed: HTTP {response.status_code}")
                return None
                
        except Exception as e:
            logger.error(f"Token verification error: {e}")
            return None


# Create token verifier
token_verifier = BlackboardTokenVerifier(blackboard_url=BLACKBOARD_URL)

# Create OAuthProxy - handles all OAuth flow automatically
auth = OAuthProxy(
    upstream_authorization_endpoint=f"{BLACKBOARD_URL}/learn/api/public/v1/oauth2/authorizationcode",
    upstream_token_endpoint=f"{BLACKBOARD_URL}/learn/api/public/v1/oauth2/token",
    upstream_client_id=BLACKBOARD_APP_KEY,
    upstream_client_secret=BLACKBOARD_APP_SECRET,
    token_verifier=token_verifier,
    base_url=SERVER_URL,
    token_endpoint_auth_method="client_secret_basic",
    forward_pkce=True,
    require_authorization_consent=True,
)

logger.info("✅ OAuthProxy configured for Blackboard with user identity extraction")

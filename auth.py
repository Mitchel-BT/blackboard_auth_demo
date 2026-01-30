"""
Blackboard OAuth Authentication for FastMCP
With comprehensive debug logging
"""
import os
import httpx
import logging
from typing import Optional, Sequence

# Enable debug logging FIRST
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Also enable FastMCP and httpx debug logging
logging.getLogger("fastmcp").setLevel(logging.DEBUG)
logging.getLogger("httpx").setLevel(logging.DEBUG)
logging.getLogger("httpcore").setLevel(logging.DEBUG)

# Environment variables
BLACKBOARD_URL = os.environ.get("BLACKBOARD_URL", "").rstrip("/")
BLACKBOARD_APP_KEY = os.environ.get("BLACKBOARD_APP_KEY")
BLACKBOARD_APP_SECRET = os.environ.get("BLACKBOARD_APP_SECRET")
SERVER_URL = os.environ.get("SERVER_URL", "").rstrip("/")

logger.info("=" * 60)
logger.info("CONFIGURATION")
logger.info("BLACKBOARD_URL: %s", BLACKBOARD_URL)
logger.info("SERVER_URL: %s", SERVER_URL)
logger.info("BLACKBOARD_APP_KEY: %s", BLACKBOARD_APP_KEY[:8] + "..." if BLACKBOARD_APP_KEY else "NOT SET")
logger.info("BLACKBOARD_APP_SECRET: %s", "SET" if BLACKBOARD_APP_SECRET else "NOT SET")
logger.info("Expected callback URL: %s/auth/callback", SERVER_URL)
logger.info("=" * 60)

if not all([BLACKBOARD_URL, BLACKBOARD_APP_KEY, BLACKBOARD_APP_SECRET, SERVER_URL]):
    raise EnvironmentError(
        "Missing required environment variables: "
        "BLACKBOARD_URL, BLACKBOARD_APP_KEY, BLACKBOARD_APP_SECRET, SERVER_URL"
    )

from mcp.server.auth.provider import AccessToken, TokenVerifier
from fastmcp.server.auth import OAuthProxy


class BlackboardTokenVerifier(TokenVerifier):
    """
    Verifies Blackboard OAuth tokens by calling Blackboard's /users/me endpoint.
    """

    def __init__(self, blackboard_url: str, required_scopes: Sequence[str] = ()):
        self.blackboard_url = blackboard_url.rstrip("/")
        self.required_scopes: list[str] = list(required_scopes) if required_scopes else ["read"]
        logger.info("BlackboardTokenVerifier initialized for %s", self.blackboard_url)

    async def verify_token(self, token: str) -> Optional[AccessToken]:
        """Verify the Blackboard access token."""
        token_len = len(token) if token else 0
        token_preview = f"{token[:12]}...{token[-4:]}" if token_len > 16 else f"[{token_len} chars]"
        
        logger.info("=" * 60)
        logger.info("TOKEN VERIFICATION CALLED")
        logger.info("Token length: %d", token_len)
        logger.info("Token preview: %s", token_preview)
        
        # Check if this looks like a JWT vs Blackboard's opaque token
        if token and token.startswith("eyJ"):
            logger.warning("⚠️ Token looks like a JWT (starts with 'eyJ')!")
            logger.warning("This might be FastMCP's internal JWT, not Blackboard's token")
        else:
            logger.info("✓ Token appears to be an opaque token (expected for Blackboard)")
        
        logger.info("=" * 60)
        
        if not token:
            logger.error("No token provided!")
            return None
        
        try:
            url = f"{self.blackboard_url}/learn/api/public/v1/users/me"
            logger.info("Calling Blackboard API: %s", url)
            
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    url,
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=15.0,
                )

            logger.info("Blackboard response status: %s", resp.status_code)
            logger.debug("Blackboard response body: %s", resp.text[:500])
            
            if resp.status_code == 401:
                logger.error("❌ Token verification failed: 401 Unauthorized")
                logger.error("The token is invalid or expired")
                return None
            
            if resp.status_code == 403:
                logger.error("❌ Token verification failed: 403 Forbidden")
                return None
            
            if resp.status_code != 200:
                logger.error("❌ Token verification failed: HTTP %s", resp.status_code)
                return None

            user_data = resp.json()
            blackboard_user_id = user_data.get("id")
            username = user_data.get("userName")

            if not blackboard_user_id:
                logger.error("❌ No user id in response")
                return None

            logger.info("✅ TOKEN VERIFIED for user: %s (%s)", blackboard_user_id, username)

            return AccessToken(
                token=token,
                client_id=BLACKBOARD_APP_KEY,
                scopes=self.required_scopes,
                claims={
                    "sub": blackboard_user_id,
                    "username": username,
                },
            )

        except Exception as e:
            logger.exception("❌ Token verification error: %s", e)
            return None


# Create the token verifier
token_verifier = BlackboardTokenVerifier(
    blackboard_url=BLACKBOARD_URL,
    required_scopes=["read"],
)

# Create OAuthProxy with explicit scope parameter for Blackboard
auth = OAuthProxy(
    upstream_authorization_endpoint=f"{BLACKBOARD_URL}/learn/api/public/v1/oauth2/authorizationcode",
    upstream_token_endpoint=f"{BLACKBOARD_URL}/learn/api/public/v1/oauth2/token",
    upstream_client_id=BLACKBOARD_APP_KEY,
    upstream_client_secret=BLACKBOARD_APP_SECRET,
    token_verifier=token_verifier,
    base_url=SERVER_URL,
    token_endpoint_auth_method="client_secret_basic",
    forward_pkce=False,  # Disable for debugging
    require_authorization_consent=True,
    valid_scopes=["read", "write", "offline"],
    # CRITICAL: Blackboard requires scope parameter
    extra_authorize_params={"scope": "read"},
)

logger.info("✅ OAuthProxy configured")
logger.info("Authorization endpoint: %s/learn/api/public/v1/oauth2/authorizationcode", BLACKBOARD_URL)
logger.info("Token endpoint: %s/learn/api/public/v1/oauth2/token", BLACKBOARD_URL)
logger.info("Callback URL (register this in Blackboard): %s/auth/callback", SERVER_URL)

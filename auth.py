import os
import httpx
import logging
from typing import Optional, Sequence

logger = logging.getLogger(__name__)

BLACKBOARD_URL = os.environ.get("BLACKBOARD_URL")
BLACKBOARD_APP_KEY = os.environ.get("BLACKBOARD_APP_KEY")
BLACKBOARD_APP_SECRET = os.environ.get("BLACKBOARD_APP_SECRET")
SERVER_URL = os.environ.get("SERVER_URL")

if not all([BLACKBOARD_URL, BLACKBOARD_APP_KEY, BLACKBOARD_APP_SECRET, SERVER_URL]):
    raise EnvironmentError("Missing required environment variables")

from mcp.server.auth.provider import AccessToken, TokenVerifier
from fastmcp.server.auth import OAuthProxy


def _parse_scopes(env_value: str | None) -> list[str]:
    """
    Supports either space-separated or comma-separated scopes.
    Examples:
      "read write offline"
      "read,write,offline"
    """
    if not env_value:
        return []
    raw = env_value.replace(",", " ").split()
    return [s.strip() for s in raw if s.strip()]


class BlackboardTokenVerifier(TokenVerifier):
    """
    Verifies Blackboard tokens and extracts user identity.
    """

    def __init__(self, blackboard_url: str, required_scopes: Sequence[str] = ()):
        self.blackboard_url = blackboard_url.rstrip("/")
        # ✅ FastMCP OAuthProxy expects this attribute to exist
        self.required_scopes: list[str] = list(required_scopes)

    async def verify_token(self, token: str) -> Optional[AccessToken]:
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    f"{self.blackboard_url}/learn/api/public/v1/users/me",
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=10.0,
                )

            if resp.status_code != 200:
                logger.warning("Token verification failed: HTTP %s", resp.status_code)
                return None

            user_data = resp.json()
            blackboard_user_id = user_data.get("id")  # e.g., "_12345_1"

            if not blackboard_user_id:
                logger.warning("Token verified but no user id returned from /users/me")
                return None

            logger.info("✅ Token verified for Blackboard user: %s", blackboard_user_id)

            # If you want FastMCP to enforce scopes, return the actual scopes granted
            # (If Blackboard doesn't return scopes reliably, you can keep your fixed list,
            # but enforcement may be misleading.)
            return AccessToken(
                token=token,
                client_id=blackboard_user_id,
                scopes=self.required_scopes,  # or parse from token/provider if available
            )

        except Exception as e:
            logger.error("Token verification error: %s", e)
            return None


# Optional: configure required scopes from env so you don't hardcode guesses
BLACKBOARD_SCOPES = _parse_scopes(os.environ.get("BLACKBOARD_SCOPES"))

token_verifier = BlackboardTokenVerifier(
    blackboard_url=BLACKBOARD_URL,
    required_scopes=BLACKBOARD_SCOPES,  # defaults to [] if env var not set
)

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

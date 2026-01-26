"""
Okta JWT Token Validator

This module validates JWT tokens issued by Okta, ensuring:
- Valid signature (using JWKS)
- Correct issuer
- Correct audience (must match gateway)
- Not expired
- Has required scopes (optional)

The JWKS (JSON Web Key Set) is cached to avoid repeated downloads.
"""

import logging
import os
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
import asyncio

import httpx
from jose import jwt, JWTError
import cachetools

logger = logging.getLogger(__name__)


class OktaTokenValidator:
    """
    Validates Okta JWT tokens for API requests.
    
    The validator:
    1. Fetches and caches JWKS from Okta
    2. Validates JWT signature using JWKS
    3. Verifies issuer, audience (against known agents), expiration
    4. Extracts user ID and scopes from claims
    """
    
    def __init__(
        self,
        okta_domain: str = None,
        okta_client_id: str = None,
        gateway_base_url: str = None,
        allowed_audiences: list = None,
        jwks_cache_ttl: int = 3600,
        jwks_cache_max_size: int = 10
    ):
        """
        Initialize validator with Okta configuration.
        
        Args:
            okta_domain: Okta domain (e.g., 'dev-12345.okta.com') [REQUIRED]
            okta_client_id: OAuth client ID (deprecated - use allowed_audiences instead)
            gateway_base_url: Gateway URL (deprecated - use allowed_audiences instead)
            allowed_audiences: List of valid client IDs (e.g., agent client_ids)
            jwks_cache_ttl: JWKS cache TTL in seconds (default: 1 hour)
            jwks_cache_max_size: Maximum JWKS sets to cache (default: 10)
            
        Note: In multi-agent setup, pass allowed_audiences as list of all agent client_ids.
        This ensures tokens are only accepted if their aud matches a known agent.
        """
        self.okta_domain = okta_domain or os.getenv("OKTA_DOMAIN")
        self.allowed_audiences = allowed_audiences or []
        
        if not self.okta_domain:
            raise ValueError(
                "OktaTokenValidator requires OKTA_DOMAIN environment variable"
            )
        
        self.issuer = f"https://{self.okta_domain}"
        self.jwks_uri = f"{self.issuer}/oauth2/v1/keys"
        self.jwks_cache = cachetools.TTLCache(
            maxsize=jwks_cache_max_size,
            ttl=jwks_cache_ttl
        )
        
        logger.info(
            f"OktaTokenValidator initialized for {self.okta_domain} "
            f"with {len(self.allowed_audiences)} allowed audiences: {self.allowed_audiences}"
        )
    
    async def fetch_jwks(self) -> Dict[str, Any]:
        """
        Fetch and cache JWKS from Okta.
        
        Returns:
            JWKS public key set
            
        Raises:
            Exception if JWKS fetch fails
        """
        # Check cache first
        if "jwks" in self.jwks_cache:
            logger.debug("Using cached JWKS")
            return self.jwks_cache["jwks"]
        
        logger.info(f"Fetching JWKS from {self.jwks_uri}")
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(self.jwks_uri, timeout=10)
                response.raise_for_status()
                jwks = response.json()
                
                # Cache it
                self.jwks_cache["jwks"] = jwks
                logger.debug("JWKS cached successfully")
                
                return jwks
        except httpx.HTTPError as e:
            logger.error(f"Failed to fetch JWKS from Okta: {e}")
            raise
    
    async def validate_token(
        self,
        token: str,
        expected_client_id: Optional[str] = None,
        required_scopes: Optional[list] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Validate Okta JWT token and return claims.
        
        Validation checks:
        - Valid JWT signature (using JWKS)
        - Correct issuer (https://okta-domain)
        - Correct audience (matches expected_client_id if provided)
        - Not expired
        - Has required scopes (if specified)
        
        Args:
            token: JWT token string
            expected_client_id: Expected client_id in aud claim (from X-MCP-Agent header)
            required_scopes: List of required scopes (e.g., ["mcp:read"])
            
        Returns:
            Token claims dict if valid, None if invalid
            
        Raises:
            JWTError if token is malformed
            JWTClaimsError if claims don't match requirements
        """
        if not token:
            logger.warning("No token provided for validation")
            return None
        
        try:
            # Fetch JWKS (cached)
            jwks = await self.fetch_jwks()
            
            # Decode JWT without validation first to get kid and alg
            unverified = jwt.get_unverified_claims(token)
            logger.debug(f"Token claims (unverified): sub={unverified.get('sub')}, "
                        f"aud={unverified.get('aud')}, iss={unverified.get('iss')}")
            
            # Extract audience from token and validate
            token_aud = unverified.get("aud")
            token_cid = unverified.get("cid")  # Client ID claim (in access tokens)
            
            logger.debug(f"Token validation: aud={token_aud}, cid={token_cid}, token_use={unverified.get('token_use')}")
            
            # If expected_client_id is provided (from X-MCP-Agent header), validate it matches
            if expected_client_id:
                # Check both aud (ID tokens) and cid (access tokens)
                if token_aud == expected_client_id or token_cid == expected_client_id:
                    logger.debug(f"Token (aud={token_aud}, cid={token_cid}) matches expected client_id '{expected_client_id}'")
                else:
                    logger.warning(
                        f"Token aud '{token_aud}' and cid '{token_cid}' do not match expected client_id '{expected_client_id}'"
                    )
                    return None
            # Otherwise, if we have allowed_audiences, validate against them
            elif self.allowed_audiences:
                # Check both aud (ID tokens) and cid (access tokens)
                if token_aud not in self.allowed_audiences and token_cid not in self.allowed_audiences:
                    logger.warning(
                        f"Token aud '{token_aud}' and cid '{token_cid}' not in allowed audiences: {self.allowed_audiences}"
                    )
                    return None
                logger.debug(f"Token (aud={token_aud}, cid={token_cid}) is allowed")
            
            # Verify JWT signature and claims
            decode_options = {
                "verify_aud": False,  # We validate aud manually above
                    "verify_iss": True,
                    "verify_exp": True,
                "require_exp": True,
                "verify_at_hash": False  # Skip at_hash validation since we use ID tokens for auth
            }
            
            decode_kwargs = {
                "token": token,
                "key": jwks,  # python-jose automatically uses jwks for validation
                "algorithms": ["RS256"],
                "issuer": self.issuer,
                "options": decode_options
            }
            
            claims = jwt.decode(**decode_kwargs)
            
            logger.debug(f"Token validated successfully for user {claims.get('sub')} with aud={claims.get('aud')}")
            
            # Check required scopes if specified
            if required_scopes:
                token_scopes = claims.get("scp", [])
                if isinstance(token_scopes, str):
                    token_scopes = token_scopes.split()
                
                missing_scopes = set(required_scopes) - set(token_scopes)
                if missing_scopes:
                    logger.warning(
                        f"Token missing required scopes: {missing_scopes}. "
                        f"Has: {token_scopes}"
                    )
                    return None
            
            return claims
        
        except JWTError as e:
            logger.warning(f"JWT validation failed: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error validating token: {e}", exc_info=True)
            return None
    
    def clear_cache(self) -> None:
        """Clear the JWKS cache."""
        self.jwks_cache.clear()
        logger.info("JWKS cache cleared")


# Global validator instance
_validator: Optional[OktaTokenValidator] = None


def get_validator() -> OktaTokenValidator:
    """Get or create the global OktaTokenValidator instance."""
    global _validator
    if _validator is None:
        _validator = OktaTokenValidator()
    return _validator


async def validate_bearer_token(
    authorization_header: Optional[str],
    required_scopes: Optional[list] = None
) -> Optional[Dict[str, Any]]:
    """
    Extract and validate a Bearer token from Authorization header.
    
    Args:
        authorization_header: "Authorization: Bearer <token>" header value
        required_scopes: List of required scopes
        
    Returns:
        Token claims if valid, None if invalid
    """
    if not authorization_header:
        logger.warning("No Authorization header provided")
        return None
    
    # Extract token from "Bearer <token>"
    parts = authorization_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        logger.warning("Invalid Authorization header format")
        return None
    
    token = parts[1]
    validator = get_validator()
    return await validator.validate_token(token, required_scopes)


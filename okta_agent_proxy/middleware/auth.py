"""
Authentication Middleware

This module provides:
1. Bearer token extraction from Authorization header
2. 401 Unauthorized responses with WWW-Authenticate header (RFC9728)
3. Request context enrichment with validated token claims
"""

import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


class UnauthorizedError(Exception):
    """Raised when authentication fails."""
    pass


def create_401_response(
    gateway_base_url: str,
    scope: str = "mcp:read mcp:write",
    error_description: str = "Invalid or missing authorization token"
) -> tuple[int, Dict[str, str], str]:
    """
    Create a 401 Unauthorized response with RFC9728 WWW-Authenticate header.
    
    The WWW-Authenticate header tells clients where to find the authorization server
    and what scopes are needed.
    
    Args:
        gateway_base_url: Gateway base URL (for metadata endpoint)
        scope: Required scopes (space-separated)
        error_description: Error description for client
        
    Returns:
        Tuple of (status_code, headers, body)
    """
    # RFC9728 WWW-Authenticate header format:
    # WWW-Authenticate: Bearer 
    #   resource_metadata="<metadata_uri>",
    #   scope="<scopes>"
    
    www_authenticate = (
        f'Bearer '
        f'resource_metadata="{gateway_base_url}/.well-known/oauth-protected-resource", '
        f'scope="{scope}", '
        f'error="invalid_token", '
        f'error_description="{error_description}"'
    )
    
    headers = {
        "WWW-Authenticate": www_authenticate,
        "Content-Type": "application/json"
    }
    
    body = {
        "error": "unauthorized",
        "error_description": error_description,
        "www_authenticate": www_authenticate
    }
    
    import json
    return (
        401,
        headers,
        json.dumps(body)
    )


def extract_bearer_token(authorization_header: Optional[str]) -> Optional[str]:
    """
    Extract Bearer token from Authorization header.
    
    Expected format: "Authorization: Bearer <token>"
    
    Args:
        authorization_header: Authorization header value
        
    Returns:
        Token string, or None if invalid format
    """
    if not authorization_header:
        logger.debug("No Authorization header provided")
        return None
    
    parts = authorization_header.split()
    if len(parts) != 2:
        logger.warning(f"Invalid Authorization header format: {len(parts)} parts")
        return None
    
    scheme, token = parts
    if scheme.lower() != "bearer":
        logger.warning(f"Invalid Authorization scheme: {scheme}")
        return None
    
    return token


class AuthContext:
    """
    Authentication context extracted from request.
    
    Contains:
    - Raw token
    - Validated claims
    - User ID
    - Scopes
    """
    
    def __init__(
        self,
        token: str,
        claims: Optional[Dict[str, Any]] = None,
        user_id: Optional[str] = None,
        scopes: Optional[list] = None,
        is_valid: bool = False
    ):
        self.token = token
        self.claims = claims or {}
        self.user_id = user_id or claims.get("sub") if claims else None
        self.scopes = scopes or []
        self.is_valid = is_valid
    
    def has_scope(self, required_scope: str) -> bool:
        """Check if token has required scope."""
        return required_scope in self.scopes
    
    def has_any_scope(self, required_scopes: list) -> bool:
        """Check if token has any of the required scopes."""
        return any(scope in self.scopes for scope in required_scopes)
    
    def has_all_scopes(self, required_scopes: list) -> bool:
        """Check if token has all required scopes."""
        return all(scope in self.scopes for scope in required_scopes)


def extract_scopes_from_claims(claims: Dict[str, Any]) -> list:
    """
    Extract scopes from JWT claims.
    
    Okta stores scopes in the "scp" claim as space-separated string or list.
    
    Args:
        claims: JWT claims dict
        
    Returns:
        List of scopes
    """
    scopes_raw = claims.get("scp", [])
    
    if isinstance(scopes_raw, str):
        # Space-separated string
        return scopes_raw.split()
    elif isinstance(scopes_raw, list):
        # Already a list
        return scopes_raw
    else:
        return []


"""
Backend MCP Server Authentication Handlers

Supports three authentication patterns for target MCP servers:

1. okta-cross-app: ID-JAG (IETF draft)
   - Exchange enterprise token for backend-specific token
   - Each user gets unique backend token
   - Token cached per user+backend

2. pre-shared-key: Static API Key
   - Static key configured in gateway
   - Same key used for all requests
   - No token caching needed
   - Simple authentication

3. service-account: Service Account Credentials
   - Gateway authenticates as service account
   - Uses Basic Auth (username:password)
   - Same auth for all requests
   - No token caching needed
"""

import logging
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any
import base64

logger = logging.getLogger(__name__)


class BackendAuthHandler(ABC):
    """Abstract base class for backend authentication handlers"""
    
    @abstractmethod
    async def get_auth_headers(self) -> Dict[str, str]:
        """
        Get Authorization header(s) for backend request
        
        Returns:
            Dict with header name -> value
            e.g., {"Authorization": "Bearer token123"}
            or {"X-API-Key": "key123"}
        """
        pass
    
    @abstractmethod
    def requires_caching(self) -> bool:
        """
        Does this auth method require token caching?
        
        True for okta-cross-app (tokens expire)
        False for static keys/service accounts (always valid)
        """
        pass


class OktaCrossAppAuthHandler(BackendAuthHandler):
    """
    Handler for Okta Cross-App Access (ID-JAG) authentication
    
    Step 1: Issue ID-JAG JWT from enterprise IdP
    Step 2: Exchange for access token at target auth server
    Token cached and reused until expiration
    """
    
    def __init__(self, access_token: str):
        """
        Initialize with already-exchanged access token
        
        Args:
            access_token: Token obtained from ID-JAG exchange
        """
        self.access_token = access_token
    
    async def get_auth_headers(self) -> Dict[str, str]:
        """
        Return Bearer token from ID-JAG exchange
        
        Returns:
            {"Authorization": "Bearer <access_token>"}
        """
        logger.debug("Using Okta Cross-App access token")
        return {
            "Authorization": f"Bearer {self.access_token}"
        }
    
    def requires_caching(self) -> bool:
        """ID-JAG tokens expire, so caching is needed"""
        return True


class PreSharedKeyAuthHandler(BackendAuthHandler):
    """
    Handler for Pre-Shared Key authentication
    
    Static API key configured at gateway
    Same key used for all requests
    Simple, stateless authentication
    """
    
    def __init__(self, key: str, header_name: str = "X-API-Key"):
        """
        Initialize with static API key
        
        Args:
            key: Static API key/secret
            header_name: Header name to use (default: "X-API-Key")
        """
        self.key = key
        self.header_name = header_name
        logger.debug(f"Pre-Shared Key auth initialized with header: {header_name}")
    
    async def get_auth_headers(self) -> Dict[str, str]:
        """
        Return static API key header
        
        Returns:
            {header_name: key}
            e.g., {"X-API-Key": "api_key_123"}
        """
        logger.debug(f"Using pre-shared key in header: {self.header_name}")
        return {
            self.header_name: self.key
        }
    
    def requires_caching(self) -> bool:
        """Pre-shared keys don't expire, no caching needed"""
        return False


class ServiceAccountAuthHandler(BackendAuthHandler):
    """
    Handler for Service Account authentication
    
    Gateway authenticates as service account
    Supports Basic Auth (username:password)
    No token caching needed
    """
    
    def __init__(self, username: str, password: str):
        """
        Initialize with service account credentials
        
        Args:
            username: Service account username/ID
            password: Service account password/secret
        """
        self.username = username
        self.password = password
        logger.debug(f"Service Account auth initialized for user: {username}")
    
    async def get_auth_headers(self) -> Dict[str, str]:
        """
        Return Basic Auth header (RFC 7617)
        
        Returns:
            {"Authorization": "Basic <base64(username:password)>"}
        """
        credentials = f"{self.username}:{self.password}"
        encoded = base64.b64encode(credentials.encode()).decode()
        logger.debug(f"Using service account Basic Auth for user: {self.username}")
        return {
            "Authorization": f"Basic {encoded}"
        }
    
    def requires_caching(self) -> bool:
        """Service account creds don't expire, no caching needed"""
        return False


def create_auth_handler(
    auth_method: str,
    auth_config: Dict[str, Any],
    access_token: Optional[str] = None
) -> Optional[BackendAuthHandler]:
    """
    Factory function to create appropriate auth handler
    
    Args:
        auth_method: "okta-cross-app", "pre-shared-key", or "service-account"
        auth_config: Auth configuration dict
        access_token: For okta-cross-app method, the already-exchanged token
        
    Returns:
        BackendAuthHandler instance or None if method unknown
    """
    if auth_method == "okta-cross-app":
        if not access_token:
            logger.error("okta-cross-app requires access_token")
            return None
        return OktaCrossAppAuthHandler(access_token)
    
    elif auth_method == "pre-shared-key":
        key = auth_config.get("key")
        if not key:
            logger.error("pre-shared-key requires 'key' in auth_config")
            return None
        header_name = auth_config.get("header_name", "X-API-Key")
        return PreSharedKeyAuthHandler(key, header_name)
    
    elif auth_method == "service-account":
        username = auth_config.get("username")
        password = auth_config.get("password")
        if not username or not password:
            logger.error("service-account requires 'username' and 'password' in auth_config")
            return None
        return ServiceAccountAuthHandler(username, password)
    
    else:
        logger.error(f"Unknown auth method: {auth_method}")
        return None


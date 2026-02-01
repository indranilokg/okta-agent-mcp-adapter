"""
Backend routing - maps request paths to appropriate MCP backend servers

Also handles:
- Backend token caching (by user + backend)
- Token exchange via Okta cross-app access (ID-JAG)
- Token expiration management
"""

import logging
import os
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
from okta_agent_proxy.config import BackendConfig
from okta_agent_proxy.cache import TokenCache
from okta_agent_proxy.auth.cross_app_access import OktaCrossAppAccessManager
from okta_agent_proxy.discovery import get_discovery_client
from okta_agent_proxy.storage import BackendConfigStore

logger = logging.getLogger(__name__)


class BackendRouter:
    """
    Routes incoming requests to appropriate backend MCP server.
    
    Maintains mappings of URL paths to backend servers.
    Example: /hr -> employees_mcp, /partners -> partners_mcp
    """
    
    def __init__(
        self,
        backends_config: Dict[str, BackendConfig],
        store: Optional[BackendConfigStore] = None
    ):
        """
        Initialize router with backend configurations.
        
        Args:
            backends_config: Dictionary of backend configurations
            store: Optional BackendConfigStore for backend lookup/updates
        """
        self.backends = backends_config
        self.store = store  # Can be used to dynamically load backends
        self._path_to_backend: Dict[str, str] = {}
        
        # Initialize token cache for backend tokens
        # Cache key: f"{user_id}:{backend_name}"
        # Value: {"token": str, "expires_at": datetime}
        self.backend_token_cache = TokenCache(
            max_size=50000,  # Cache up to 50k tokens
            ttl_seconds=3600  # Default TTL (can vary by token)
        )
        
        # Cross-app access manager (will be initialized per agent in proxy handler)
        self.cross_app_manager = None
        
        # Get discovery client for dynamic auth server discovery
        self.discovery_client = get_discovery_client()
        
        # Build path -> backend mapping
        for backend_name, backend_config in backends_config.items():
            for path in backend_config.paths:
                self._path_to_backend[path] = backend_name
                logger.info(f"Route registered: {path} -> {backend_name} ({backend_config.url})")
    
    def get_backend_for_path(self, path: str) -> Optional[str]:
        """
        Get backend name for a request path.
        
        Args:
            path: Request path (e.g., "/hr", "/partners")
        
        Returns:
            Backend name or None if path not found
        """
        # Direct match
        if path in self._path_to_backend:
            return self._path_to_backend[path]
        
        # Try matching with /mcp stripped (common in MCP requests)
        path_without_mcp = path.replace("/mcp", "", 1)
        if path_without_mcp in self._path_to_backend:
            return self._path_to_backend[path_without_mcp]
        
        # Extract base path (e.g., /hr from /hr/mcp)
        parts = path.split("/")
        if len(parts) > 1:
            base_path = "/" + parts[1]
            if base_path in self._path_to_backend:
                return self._path_to_backend[base_path]
        
        logger.warning(f"No backend found for path: {path}")
        return None
    
    def get_backend_config(self, backend_name: str) -> Optional[BackendConfig]:
        """
        Get configuration for a backend.
        
        Args:
            backend_name: Backend identifier
        
        Returns:
            BackendConfig or None if not found
        """
        return self.backends.get(backend_name)
    
    def get_backend_url(self, backend_name: str) -> Optional[str]:
        """
        Get URL for a backend.
        
        Args:
            backend_name: Backend identifier
        
        Returns:
            Backend URL or None if not found
        """
        config = self.get_backend_config(backend_name)
        return config.url if config else None
    
    def list_backends(self) -> Dict[str, Dict]:
        """
        List all registered backends.
        
        Returns:
            Dictionary with backend info
        """
        result = {}
        for backend_name, config in self.backends.items():
            result[backend_name] = {
                "url": config.url,
                "description": config.description,
                "paths": config.paths,
                "timeout_seconds": config.timeout_seconds
            }
        return result
    
    def list_routes(self) -> Dict[str, str]:
        """
        List all registered routes.
        
        Returns:
            Dictionary mapping paths to backend names
        """
        return dict(self._path_to_backend)
    
    async def get_backend_token(
        self,
        user_id: str,
        backend_name: str,
        user_id_token: str,
        agent_config: Optional[Dict[str, Any]] = None,
        force_refresh: bool = False
    ) -> Optional[str]:
        """
        Get backend token via cache or ID-JAG flow using OktaAISDK.
        
        Implements IETF Identity Assertion Authorization Grant (ID-JAG) pattern:
        https://www.ietf.org/archive/id/draft-ietf-oauth-identity-assertion-authz-grant-00.html
        
        3-step flow via OktaCrossAppAccessManager:
        1. Exchange ID Token for ID-JAG token (org auth server)
        2. Verify ID-JAG token (optional)
        3. Exchange ID-JAG for target auth server token
        
        Cache:
        1. Check cache for existing access token
        2. If cached token valid, return it
        3. Otherwise, perform ID-JAG flow
        4. Cache new token with TTL
        5. Return access token
        
        Args:
            user_id: User identifier (from JWT sub claim)
            backend_name: Backend MCP server name
            user_id_token: User's ID token from agent/client authentication
            agent_config: Agent configuration dict with agent_id, client_id, private_key
            force_refresh: Force token refresh even if cached
            
        Returns:
            Access token for backend or None if exchange fails
            
        Raises:
            ValueError if backend not found
        """
        # Build cache key components
        # Try cache first (unless force_refresh)
        if not force_refresh:
            cached = self.backend_token_cache.get(user_id, backend_name)
            if cached:
                token_data = cached
                if isinstance(token_data, dict) and "token" in token_data:
                    # Check if token is still valid
                    expires_at = token_data.get("expires_at")
                    if expires_at and datetime.now() < expires_at:
                        logger.debug(
                            f"Using cached backend token for {user_id}:{backend_name}"
                        )
                        return token_data["token"]
        
        # Get backend config
        backend_config = self.get_backend_config(backend_name)
        if not backend_config:
            logger.error(f"Backend not found: {backend_name}")
            raise ValueError(f"Backend '{backend_name}' not found")
        
        # Check if backend requires authentication
        auth_method = getattr(backend_config, "auth_method", None)
        if auth_method != "okta-cross-app":
            logger.warning(f"Backend {backend_name} does not use okta-cross-app auth")
            return user_id_token  # Return user token as fallback
        
        # Get auth configuration
        auth_config = getattr(backend_config, "auth_config", {})
        logger.info(f"Backend {backend_name} auth_config type: {type(auth_config)}, value: {auth_config}")
        
        # Convert Pydantic model to dict if needed
        if hasattr(auth_config, "model_dump"):
            # Pydantic v2
            auth_config = auth_config.model_dump()
        elif hasattr(auth_config, "dict"):
            # Pydantic v1
            auth_config = auth_config.dict()
        elif not isinstance(auth_config, dict):
            logger.warning(f"Backend {backend_name} invalid auth_config format - expected dict or Pydantic model, got {type(auth_config)}")
            logger.warning(f"Backend {backend_name} config object: {backend_config}")
            return None
        
        logger.info(f"Converted auth_config to dict: {auth_config}")
        
        # Determine ID-JAG mode (static or dynamic)
        id_jag_mode = auth_config.get("id_jag_mode", "static")
        target_authorization_server = auth_config.get("target_authorization_server")
        
        # For dynamic mode, discover auth server details from target
        if id_jag_mode == "dynamic":
            logger.info(f"Using DYNAMIC ID-JAG mode for {backend_name}")
            
            discovered = await self.discovery_client.extract_auth_server_details(
                backend_config.url,
                force_refresh=False
            )
            
            if not discovered:
                logger.error(f"Failed to discover auth server details for {backend_name}")
                return None
            
            target_authorization_server = discovered.get("target_authorization_server")
            logger.info(
                f"Discovered auth server for {backend_name}: {target_authorization_server}"
            )
        else:
            logger.info(f"Using STATIC ID-JAG mode for {backend_name}")
            
            if not target_authorization_server:
                logger.error(
                    f"Static ID-JAG mode requires target_authorization_server for {backend_name}"
                )
                return None
        
        # Use OktaCrossAppAccessManager for token exchange
        try:
            # Check if backend has client credentials configured
            has_client_creds = bool(auth_config.get("target_client_id") and auth_config.get("target_client_secret"))
            logger.info(f"Has client credentials: {has_client_creds}, ID-JAG mode: {id_jag_mode}")
            
            # Get authorization server ID from config
            # For static mode, it's configured in auth_config
            # For dynamic mode, it's discovered from backend
            target_auth_server_id = target_authorization_server.split("/oauth2/")[-1] if target_authorization_server else None
            if not target_auth_server_id:
                logger.error(f"Cannot extract authorization server ID from {target_authorization_server}")
                return None
            
            logger.info(f"Target auth server ID: {target_auth_server_id}")
            
            logger.info(
                f"Exchanging token for {user_id} -> {backend_name} "
                f"(target auth server: {target_authorization_server})"
            )
            logger.debug(f"User ID token (first 50 chars): {user_id_token[:50] if user_id_token else 'None'}...")
            logger.info(f"Auth config for {backend_name}: {auth_config}")
            
            if has_client_creds:
                # Full ID-JAG flow with client credentials (RFC7523)
                logger.debug(f"Using full ID-JAG flow (RFC7523 JWT Bearer) for {backend_name}")
                result = await self._exchange_id_jag_full(
                    user_id_token,  # ID token from agent/client login
                    target_authorization_server,
                    backend_config.url,
                    auth_config
                )
            else:
                # Simple ID-JAG exchange using Okta AI SDK
                # Uses agent credentials for JWT signing, exchanges ID token for MCP token
                logger.debug(f"Using simple ID-JAG flow (Okta AI SDK) for {backend_name}")
                
                # Check if agent_config is available
                if not agent_config:
                    logger.error(f"Cannot use simple ID-JAG flow: agent_config not provided")
                    logger.info(f"Static ID-JAG requires an explicit agent via X-MCP-Agent header")
                    return None
                
                # Initialize cross-app access manager if not already done
                # Pass agent credentials from agent_config (can be dict or object)
                # Extract agent credentials from agent_config
                try:
                    agent_id = agent_config.get("agent_id") if isinstance(agent_config, dict) else agent_config.agent_id
                    agent_private_key = agent_config.get("private_key") if isinstance(agent_config, dict) else agent_config.private_key
                    agent_client_id = agent_config.get("client_id") if isinstance(agent_config, dict) else agent_config.client_id
                    okta_domain = os.getenv("OKTA_DOMAIN")
                    
                    logger.debug(f"Creating OktaCrossAppAccessManager for {backend_name} with agent={agent_id}")
                    # Create a LOCAL (non-cached) instance
                    cross_app_manager = OktaCrossAppAccessManager(
                        agent_id=agent_id,
                        client_id=agent_client_id,
                        agent_private_key=agent_private_key,
                        okta_domain=okta_domain,
                        target_auth_server_id=target_auth_server_id
                    )
                except Exception as e:
                    logger.error(f"Failed to initialize OktaCrossAppAccessManager: {e}", exc_info=True)
                    return None
                
                result = await cross_app_manager.exchange_id_token_to_mcp_token(
                    user_id_token=user_id_token,
                    backend_name=backend_name,
                    target_auth_server_id=target_auth_server_id,
                    scopes=None  # Scopes will be determined by Okta policies
                )
            
            if not result or not result.get("access_token"):
                logger.error(f"Failed to exchange token for {backend_name}")
                logger.error(f"OAuth exchange result: {result}")
                return None
            
            access_token = result["access_token"]
            expires_in = result.get("expires_in", 3600)
            logger.info(f"Successfully obtained backend access token for {backend_name}, expires in {expires_in}s")
            
            # Cache token with expiration
            expires_at = datetime.now() + timedelta(seconds=expires_in - 60)  # Refresh 60s before expiry
            token_data = {
                "token": access_token,
                "expires_at": expires_at,
                "expires_in": expires_in
            }
            
            self.backend_token_cache.set(user_id, backend_name, token_data, ttl_seconds=expires_in)
            
            logger.info(
                f"Token exchange complete for {user_id}:{backend_name}, "
                f"access token cached for {expires_in}s"
            )
            
            return access_token
        
        except Exception as e:
            logger.error(
                f"Failed to complete token exchange for {user_id} -> {backend_name}: {e}",
                exc_info=True
            )
            return None
    
    async def _exchange_id_jag_full(
        self,
        user_id_token: str,
        target_auth_server: str,
        backend_url: str,
        auth_config: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Full ID-JAG flow with client credentials (RFC7523 JWT Bearer).
        Uses OktaCrossAppAccessManager with user's ID token.
        """
        # Extract auth server ID from target_authorization_server URL
        # E.g., https://domain.okta.com/oauth2/ausscimnps4vnh9zE1d7 -> ausscimnps4vnh9zE1d7
        auth_server_id = target_auth_server.split('/')[-1]
        
        result = await self.cross_app_manager.exchange_id_token_to_mcp_token(
            user_id_token=user_id_token,
            backend_name=backend_url,  # Using backend URL as identifier
            target_auth_server_id=auth_server_id,
            scopes=scopes
        )
        return result
    
    async def _exchange_id_jag_simple(
        self,
        user_id_token: str,
        target_auth_server: str,
        backend_url: str,
        auth_config: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Simple ID-JAG flow without client credentials.
        The user's ID token itself becomes the ID-JAG assertion.
        Target auth server validates it and returns an access token with the specified audience.
        
        This is used when the target MCP only needs to validate the token
        against its auth server and doesn't require additional JWT bearer exchange.
        Works with any agent (Cursor, Claude, Copilot, custom agents, etc.)
        """
        import httpx
        
        target_audience = auth_config.get("target_audience", backend_url)
        
        logger.debug(f"Simple ID-JAG: ID token as assertion, audience={target_audience}")
        
        # Extract auth server endpoint from target_authorization_server
        # E.g., https://domain.okta.com/oauth2/server-id -> https://domain.okta.com/oauth2/server-id/v1/token
        token_endpoint = f"{target_auth_server}/v1/token"
        
        try:
            async with httpx.AsyncClient() as client:
                # Exchange ID-JAG (ID token) for MCP access token
                # No client credentials needed - just assertion + audience
                response = await client.post(
                    token_endpoint,
                    data={
                        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                        "subject_token": user_id_token,
                        "subject_token_type": "urn:ietf:params:oauth:token-type:id_jag",
                        "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
                        "audience": target_audience,
                    },
                    timeout=10
                )
                
                if response.status_code != 200:
                    logger.error(
                        f"Simple ID-JAG exchange failed: {response.status_code} - {response.text}"
                    )
                    return None
                
                result = response.json()
                logger.info(
                    f"Simple ID-JAG exchange success: token expires_in={result.get('expires_in')}s"
                )
                
                return {
                    "access_token": result.get("access_token"),
                    "expires_in": result.get("expires_in", 3600),
                    "token_type": result.get("token_type", "Bearer"),
                    "scope": result.get("scope")
                }
        
        except Exception as e:
            logger.error(f"Simple ID-JAG exchange error: {e}", exc_info=True)
            return None
    
    def invalidate_backend_token(self, user_id: str, backend_name: str) -> None:
        """
        Invalidate cached backend token (e.g., after 401 error).
        
        Forces a new token exchange on next request.
        
        Args:
            user_id: User identifier
            backend_name: Backend name
        """
        cache_key = f"{user_id}:{backend_name}"
        self.backend_token_cache.delete(cache_key)
        logger.info(f"Invalidated backend token cache for {user_id}:{backend_name}")
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """
        Get backend token cache statistics.
        
        Returns:
            Cache stats dict
        """
        return self.backend_token_cache.stats()


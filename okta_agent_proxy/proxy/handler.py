"""
MCP Request Proxy Handler

Handles complete MCP request flow:
1. Token validation (from Phase 2)
2. Backend token exchange (from Phase 3)
3. Request forwarding to backend
4. Response propagation
5. Error handling (401, timeouts, etc.)
"""

import logging
import json
from typing import Optional, Dict, Any
import httpx

from okta_agent_proxy.auth.okta_validator import OktaTokenValidator
from okta_agent_proxy.middleware.auth import extract_bearer_token, extract_scopes_from_claims
from okta_agent_proxy.backends import BackendRouter
from okta_agent_proxy.auth.backend_auth import create_auth_handler
from okta_agent_proxy.storage import BackendConfigStore
from okta_agent_proxy.config import AgentConfig
from okta_agent_proxy.middleware.agent_extractor import AgentExtractor
from okta_agent_proxy.auth.agent_authz import (
    check_agent_can_access_backend,
    AgentAuthorizationError,
    create_authorization_error_response,
    create_missing_agent_error_response,
    create_invalid_agent_header_response
)
from okta_agent_proxy.proxy.session_manager import MCPSessionManager

logger = logging.getLogger(__name__)


class ProxyHandler:
    """
    Proxies MCP requests to appropriate backend MCP server.
    
    Handles:
    - Token validation against Okta
    - Token exchange for backend (ID-JAG)
    - Request routing and forwarding
    - Error propagation
    """
    
    def __init__(
        self,
        router: BackendRouter,
        okta_validator: OktaTokenValidator,
        store: Optional[BackendConfigStore] = None,
        http_timeout: float = 30.0,
        session_ttl: int = 3600
    ):
        """
        Initialize proxy handler.
        
        Args:
            router: BackendRouter instance for routing and token exchange
            okta_validator: OktaTokenValidator for JWT validation
            store: Optional BackendConfigStore for agent lookup
            http_timeout: HTTP request timeout in seconds
            session_ttl: MCP session TTL in seconds (default: 1 hour)
        """
        self.router = router
        self.okta_validator = okta_validator
        self.store = store
        self.http_timeout = http_timeout
        self.agent_extractor = AgentExtractor(store) if store else None
        self.session_manager = MCPSessionManager(session_ttl=session_ttl)
        logger.info(f"ProxyHandler initialized with session_ttl={session_ttl}s")
    
    async def proxy_request(
        self,
        request_path: str,
        method: str,
        params: Optional[Dict[str, Any]],
        auth_header: Optional[str],
        request_id: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Proxy a complete MCP request to appropriate backend.
        
        Flow:
        1. Extract and validate Bearer token from auth header
        2. Determine backend from request path
        3. Exchange token for backend (if needed)
        4. Forward request to backend
        5. Handle response or error
        
        Args:
            request_path: Request path (e.g., "/hr/mcp", "/partners")
            method: MCP method (e.g., "tools/list", "tools/call")
            params: Method parameters
            auth_header: Authorization header value
            request_id: Optional request ID
            
        Returns:
            Response dict (result or error)
        """
        # Step 1: Validate token
        if not auth_header:
            logger.warning("No Authorization header provided")
            return {
                "error": "unauthorized",
                "message": "Authorization header required"
            }
        
        # Extract Bearer token
        token = extract_bearer_token(auth_header)
        if not token:
            logger.warning("Invalid Authorization header format")
            return {
                "error": "unauthorized",
                "message": "Invalid Authorization header format"
            }
        
        # Extract agent name from X-MCP-Agent header to get expected client_id
        expected_client_id = None
        if headers:
            agent_name = headers.get("x-mcp-agent") or headers.get("X-MCP-Agent")
            if agent_name and agent_name in self.store.get_all_agents(enabled_only=False):
                agent = self.store.get_agent(agent_name)
                if agent:
                    expected_client_id = agent.client_id
                    logger.debug(f"Agent '{agent_name}' mapped to client_id '{expected_client_id}'")
        
        # Validate token with Okta
        # Pass expected_client_id to validate aud claim matches the agent
        claims = await self.okta_validator.validate_token(token, expected_client_id=expected_client_id)
        if not claims:
            logger.warning(f"Token validation failed for method {method}")
            return {
                "error": "unauthorized",
                "message": "Invalid or expired token"
            }
        
        user_id = claims.get("sub")
        scopes = extract_scopes_from_claims(claims)
        logger.debug(
            f"User {user_id} authenticated with scopes: {scopes}"
        )
        
        # Extract agent ID (optional, for multi-agent support)
        agent_id = None
        agent_config = None
        
        # Try to get agent from X-MCP-Agent header (case-insensitive)
        if headers:
            # Check multiple header variations
            for header_name in ["X-MCP-Agent", "x-mcp-agent", "X-MCP-AGENT", "MCP-Agent"]:
                if header_name in headers:
                    agent_id = headers[header_name]
                    logger.debug(f"Found agent header: {header_name}={agent_id}")
                    break
        
        # Get agent config from store if agent_id is known
        if agent_id and self.store:
            # Look up agent by NAME (agent_id from header is the agent name like "claude-code")
            agent_config = self.store.get_agent_by_name(agent_id)
            if agent_config:
                # Get client_id safely (could be dict or object)
                client_id = agent_config.get("client_id") if isinstance(agent_config, dict) else agent_config.client_id
                logger.info(f"Agent '{agent_id}' found from header (client_id={client_id})")
            else:
                logger.warning(f"Agent '{agent_id}' specified in header but not found in config")
                return create_missing_agent_error_response(f"Agent '{agent_id}' not found")
        
        # Fallback: Try to find agent by token's aud claim (client_id)
        # WARNING: This is only reliable if each client_id is unique per agent!
        if not agent_config and claims and self.store:
            token_aud = claims.get("aud")
            if token_aud:
                logger.debug(f"Agent not in header, attempting fallback lookup by token aud: {token_aud}")
                all_agents = self.store.get_all_agents(enabled_only=False)
                matches = []
                for agent_name in all_agents:
                    agent = self.store.get_agent(agent_name)
                    if agent:
                        # Handle both dict and object types
                        agent_client_id = agent.get("client_id") if isinstance(agent, dict) else agent.client_id
                        if agent_client_id == token_aud:
                            matches.append((agent_name, agent))
                
                if len(matches) == 1:
                    agent_id, agent_config = matches[0]
                    logger.info(f"Found agent by token aud (fallback): {agent_id}")
                elif len(matches) > 1:
                    logger.error(f"Multiple agents with client_id {token_aud}: {[m[0] for m in matches]}. Cannot proceed without explicit agent header.")
                    return {
                        "error": "ambiguous_agent",
                        "message": f"Multiple agents match token. Please include X-MCP-Agent header in requests."
                    }
                else:
                    logger.warning(f"Token aud {token_aud} does not match any configured agent")
        
        # Step 2: Route to backend based on path
        backend_name = self.router.get_backend_for_path(request_path)
        if not backend_name:
            logger.warning(f"No backend found for path: {request_path}")
            return {
                "error": "backend_not_found",
                "message": f"No backend configured for path '{request_path}'"
            }
        
        # Step 3: Verify agent has access to this backend (if agent is known)
        if agent_config:
            # Handle both dict and object types
            backend_access = agent_config.get("backend_access") if isinstance(agent_config, dict) else agent_config.backend_access
            if backend_access and backend_name not in backend_access:
                logger.warning(f"Agent '{agent_id}' does not have access to backend '{backend_name}'")
                return {
                    "error": "forbidden",
                    "message": f"Agent '{agent_id}' does not have access to backend '{backend_name}'"
                }
        
        logger.debug(f"Agent '{agent_id}' has access to backend '{backend_name}'")
        
        backend_config = self.router.get_backend_config(backend_name)
        if not backend_config:
            return {
                "error": "backend_not_found",
                "message": f"Backend '{backend_name}' configuration not found"
            }
        
        backend_url = backend_config.url
        auth_method = backend_config.auth_method
        logger.info(f"Routing {method} to backend '{backend_name}' (auth: {auth_method}) for user {user_id}")
        
        # Check agent authorization for backend (if agent is configured)
        if agent_id and agent_config:
            try:
                check_agent_can_access_backend(agent_id, agent_config, backend_name)
                logger.debug(f"Agent {agent_id} authorized for backend {backend_name}")
            except AgentAuthorizationError as e:
                logger.warning(f"Authorization denied: {e}")
                return create_authorization_error_response(e)
        
        # Step 3: Get authentication handler for backend
        auth_handler = None
        
        if auth_method == "okta-cross-app":
            # Get backend token via ID-JAG exchange
            # If agent_config is available, pass it for agent-specific credentials
            # Note: agent_config can be dict or object, router will handle it
            backend_token = await self.router.get_backend_token(
                user_id=user_id,
                backend_name=backend_name,
                user_id_token=token,  # ID token from any agent (Cursor, Claude, Copilot, etc.)
                agent_config=agent_config  # Pass as-is (dict or object)
            )
            
            if not backend_token:
                logger.error(f"Failed to obtain backend token for {backend_name}")
                return {
                    "error": "token_exchange_failed",
                    "message": f"Could not exchange token for backend '{backend_name}'"
                }
            
            # Create auth handler with the exchanged token
            auth_handler = create_auth_handler(
                auth_method="okta-cross-app",
                auth_config={},
                access_token=backend_token
            )
        
        elif auth_method == "pre-shared-key":
            # Use static API key
            auth_handler = create_auth_handler(
                auth_method="pre-shared-key",
                auth_config=backend_config.auth_config.model_dump()
            )
        
        elif auth_method == "service-account":
            # Use service account credentials
            auth_handler = create_auth_handler(
                auth_method="service-account",
                auth_config=backend_config.auth_config.model_dump()
            )
        
        else:
            logger.error(f"Unknown auth method for {backend_name}: {auth_method}")
            return {
                "error": "invalid_auth_method",
                "message": f"Unknown auth method: {auth_method}"
            }
        
        if not auth_handler:
            logger.error(f"Failed to create auth handler for {backend_name}")
            return {
                "error": "auth_handler_failed",
                "message": f"Could not create authentication handler for backend '{backend_name}'"
            }
        
        # Step 4: Forward to backend
        try:
            logger.debug(
                f"Forwarding {method} request to {backend_name} at {backend_url}"
            )
            
            # Build JSON-RPC request for backend
            backend_request = {
                "jsonrpc": "2.0",
                "id": request_id or "1",
                "method": method,
            }
            if params:
                backend_request["params"] = params
            
            # Get auth headers from handler
            auth_headers = await auth_handler.get_auth_headers()
            
            # Create or get MCP session
            session_id = await self.session_manager.get_or_create_session(
                user_id=user_id,
                backend_name=backend_name,
                backend_url=backend_url,
                access_token=backend_token if auth_method == "okta-cross-app" else ""
            )
            
            if not session_id:
                logger.error(f"Failed to create MCP session for {backend_name}")
                return {
                    "error": "session_creation_failed",
                    "message": f"Could not create MCP session for backend '{backend_name}'"
                }
            
            # Add session ID to headers
            request_headers = {
                **auth_headers,
                "Content-Type": "application/json",
                "Mcp-Session-Id": session_id
            }
            
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    backend_url,
                    json=backend_request,
                    headers=request_headers,
                    timeout=self.http_timeout
                )
            
            # Step 5: Handle response
            if response.status_code == 401:
                # Backend rejected token - invalidate cache and session, return 401 to client
                logger.warning(
                    f"Backend returned 401 for {user_id} on {backend_name}"
                )
                self.router.invalidate_backend_token(user_id, backend_name)
                self.session_manager.invalidate_session(user_id, backend_name)
                return {
                    "error": "backend_unauthorized",
                    "message": f"Backend rejected authentication"
                }
            
            elif response.status_code == 200:
                # Successful response from backend
                result = response.json()
                logger.debug(f"Backend {backend_name} returned 200 OK for {method}")
                
                # Log tools count if it's a tools/list response
                if method == "tools/list" and "result" in result:
                    tools = result["result"].get("tools", [])
                    logger.info(f"Backend returned {len(tools)} tools")
                
                return result.get("result", result)
            
            else:
                # Other HTTP error from backend
                logger.error(
                    f"Backend {backend_name} returned {response.status_code}: "
                    f"{response.text}"
                )
                return {
                    "error": f"backend_http_{response.status_code}",
                    "message": f"Backend returned HTTP {response.status_code}"
                }
        
        except httpx.TimeoutException:
            logger.error(f"Timeout connecting to backend {backend_name}")
            return {
                "error": "backend_timeout",
                "message": f"Backend '{backend_name}' did not respond in time"
            }
        
        except httpx.RequestError as e:
            logger.error(
                f"Network error connecting to {backend_name}: {e}",
                exc_info=True
            )
            return {
                "error": "backend_connection_error",
                "message": f"Could not connect to backend '{backend_name}'"
            }
        
        except Exception as e:
            logger.error(
                f"Error proxying request to {backend_name}: {e}",
                exc_info=True
            )
            return {
                "error": "proxy_error",
                "message": str(e)
            }


# Global proxy handler instance
_proxy_handler: Optional[ProxyHandler] = None


def get_proxy_handler(
    router: Optional[BackendRouter] = None,
    validator: Optional[OktaTokenValidator] = None,
    store: Optional[BackendConfigStore] = None
) -> ProxyHandler:
    """
    Get or create the global ProxyHandler instance.
    
    Args:
        router: BackendRouter instance (required on first call)
        validator: OktaTokenValidator instance (required on first call)
        store: Optional BackendConfigStore for agent lookup
        
    Returns:
        ProxyHandler instance
    """
    global _proxy_handler
    if _proxy_handler is None:
        if not router or not validator:
            raise ValueError(
                "router and validator required on first ProxyHandler creation"
            )
        _proxy_handler = ProxyHandler(router, validator, store)
    return _proxy_handler


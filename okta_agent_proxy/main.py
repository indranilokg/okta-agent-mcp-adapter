"""
Okta Agent Proxy - Main entry point

A transparent proxy gateway for Model Context Protocol servers with Okta authentication.
Supports multiple backend MCP servers and path-based routing.

The gateway acts as a transparent proxy, forwarding all MCP protocol requests
to the backend while handling authentication and session management.
"""

import os
import logging
import json
from typing import Optional, Dict, Any

from fastmcp import FastMCP, Context
import httpx

from okta_agent_proxy.config import load_config, GatewaySettings
from okta_agent_proxy.backends import BackendRouter
from okta_agent_proxy.cache import TokenCache
from okta_agent_proxy.middleware import setup_logging
from okta_agent_proxy.metadata import get_protected_resource_metadata
from okta_agent_proxy.auth.okta_validator import OktaTokenValidator, validate_bearer_token
from okta_agent_proxy.middleware.auth import (
    extract_bearer_token,
    extract_scopes_from_claims,
    create_401_response,
    AuthContext
)
from okta_agent_proxy.middleware.mcp_transparent_proxy import should_forward_to_backend
from okta_agent_proxy.proxy import ProxyHandler
from okta_agent_proxy.storage import InMemoryBackendStore
from okta_agent_proxy.admin.config_manager import ConfigManager
from okta_agent_proxy.admin import routes as admin_routes

# Setup logging
setup_logging()
logger = logging.getLogger(__name__)

# Global instances
config = load_config()

# Initialize backend configuration store (Phase 1B)
# Loads backends and agents from YAML, stores in SQLite in-memory database
config_path = os.getenv("CONFIG_PATH", "config/config.yaml")
store = InMemoryBackendStore(config_path)
logger.info(f"Loaded {len(store.get_all_backends())} backends from {config_path}")
logger.info(f"Loaded {len(store.get_all_agents(enabled_only=False))} agents from {config_path}")

# Initialize admin config manager for managing config.yaml
config_manager = ConfigManager(config_path)
admin_routes.set_config_manager(config_manager)
logger.info("Admin config manager initialized")

# Initialize router with store for backend lookup
router = BackendRouter(config.backends, store=store)

# Initialize token cache
token_cache = TokenCache(
    max_size=config.cache.max_size,
    ttl_seconds=config.cache.ttl_seconds
)

# Create Okta token validator using loaded gateway settings
# Pass all agent client_ids as allowed audiences for validation
allowed_audiences = [agent.client_id for agent in config.agents.values()]
okta_validator = OktaTokenValidator(
    okta_domain=config.gateway.okta_domain,
    allowed_audiences=allowed_audiences
)

# Create proxy handler with store for agent support (Phase 2)
proxy_handler = ProxyHandler(router, okta_validator, store=store)

# Create FastMCP server without RemoteAuthProvider
# We'll serve OAuth discovery endpoints manually via custom resources
mcp = FastMCP(
    name=config.name
)

# Track gateway info
gateway_settings = config.gateway


# ============================================================================
# MCP Protocol Utilities
# ============================================================================

def get_gateway_icon():
    """
    Get gateway icon for MCP initialization response.
    Per MCP spec 2025-11-25: icons property provides visual identifiers.
    Returns an SVG data URI for the Okta Agent Proxy icon.
    """
    return {
        "src": "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Ccircle cx='50' cy='50' r='45' fill='%23003366'/%3E%3Ctext x='50' y='60' text-anchor='middle' font-size='40' fill='white' font-family='Arial'%3EOA%3C/text%3E%3C/svg%3E",
        "mimeType": "image/svg+xml",
        "theme": "light"
    }


def preserve_meta_in_response(request_body: Dict[str, Any], response: Dict[str, Any]) -> Dict[str, Any]:
    """
    Preserve _meta property from request to response if present.
    Per MCP spec 2025-11-25: _meta is reserved for client/server metadata.
    
    The gateway should forward _meta from request params to response result
    to preserve context across the call chain.
    """
    request_params = request_body.get("params", {})
    if isinstance(request_params, dict) and "_meta" in request_params:
        meta = request_params.get("_meta")
        
        # Add _meta to response result if there is a result
        if "result" in response and isinstance(response["result"], dict):
            response["result"]["_meta"] = meta
            logger.debug(f"Preserved _meta in response: {list(meta.keys()) if isinstance(meta, dict) else 'non-dict'}")
    
    return response


# ============================================================================
# MCP Protocol Interception Middleware
# ============================================================================

# This middleware is applied at the ASGI level to intercept MCP requests
# and enforce authentication before forwarding to FastMCP


# ============================================================================
# OAuth Discovery Endpoints (RFC9728)
# ============================================================================

@mcp.resource(uri="mcp://oauth-protected-resource")
def protected_resource_metadata_resource() -> str:
    """
    Protected Resource Metadata endpoint (RFC9728).
    
    Clients discover this endpoint to learn:
    1. Where the authorization server is (Okta)
    2. What documentation is available
    3. Metadata about the protected resource
    
    This resource is accessible at: /.well-known/oauth-protected-resource
    """
    import json
    metadata = get_protected_resource_metadata()
    return json.dumps(metadata, indent=2)


# ============================================================================
# Authenticated Backend Proxy Tools
# ============================================================================

@mcp.tool(name="backend_tools_list")
async def backend_tools_list() -> Dict[str, Any]:
    """
    List available backend tools and services.
    
    PROTECTED BY OAUTH: Requires valid Okta bearer token.
    Clients must authenticate via mcp://oauth-protected-resource endpoint first.
    """
    logger.info("backend_tools_list called")
    
    # Return info about available backends
    return {
        "status": "success",
        "backends": {
            "employees": {
                "url": "https://okta-sample-employee-mcp-server.onrender.com/mcp",
                "description": "Employee information database",
                "available_tools": [
                    "list_employees",
                    "search_employees"
                ]
            }
        },
        "note": "Backend tools are protected by OAuth. Your bearer token is automatically included in requests."
    }


@mcp.resource(uri="mcp://oauth-protected-resource")
def protected_resource_metadata_resource() -> str:
    """
    Protected Resource Metadata endpoint (RFC9728).
    
    Returns metadata pointing to the GATEWAY as the authorization server
    (not Okta directly). This allows the gateway to serve both OAuth discovery
    and client registration endpoints.
    """
    import json
    metadata = {
        "authorization_servers": [config.gateway.gateway_base_url],
        "scopes_supported": ["openid", "offline_access"],
        "bearer_methods_supported": ["header"]
    }
    return json.dumps(metadata, indent=2)


@mcp.tool(name="dcr_discovery")
async def dcr_discovery(agent: Optional[str] = None) -> Dict[str, Any]:
    """
    Dynamic Client Registration (DCR) discovery endpoint.
    
    Returns protected resource metadata with client registration info for the specified agent.
    If no agent is specified, returns available agents.
    
    Args:
        agent: Agent name (e.g., "claude-code", "cursor") - optional
    
    Returns:
        Protected resource metadata with agent client registration details
    """
    if not agent:
        # Return list of available agents
        available_agents = {}
        for agent_name, agent_config in config.agents.items():
            available_agents[agent_name] = {
                "agent_id": agent_config.agent_id,
                "client_id": agent_config.client_id,
                "enabled": agent_config.enabled,
                "description": f"Agent: {agent_name}"
            }
        return {
            "status": "available_agents",
            "agents": available_agents
        }
    
    # Return metadata for specific agent
    if agent not in config.agents:
        return {
            "error": "agent_not_found",
            "message": f"Agent '{agent}' not found in configuration",
            "available_agents": list(config.agents.keys())
        }
    
    agent_config = config.agents[agent]
    
    # Get base OAuth metadata
    metadata = auth.get_protected_resource_metadata()
    
    # Add agent-specific client registration info
    metadata["client_registration"] = {
        "agent_name": agent,
        "agent_id": agent_config.agent_id,
        "client_id": agent_config.client_id,
        "client_name": f"Okta Agent Proxy - {agent}",
        "redirect_uris": ["http://localhost:*/callback", "http://127.0.0.1:*/callback"],
        "response_types": ["code", "id_token", "token"],
        "grant_types": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_method": "client_secret_basic",
        "scopes_requested": ["openid", "profile", "email", "offline_access"]
    }
    
    return {
        "status": "success",
        "agent": agent,
        "protected_resource_metadata": metadata
    }


# ============================================================================
# Entry Point
# ============================================================================

def run(
    host: str = None,
    port: int = None,
    transport: str = "http"
) -> None:
    """
    Run the MCP gateway server.
    
    Args:
        host: Server host (default from config)
        port: Server port (default from config)
        transport: Transport type ("http" or "stdio")
    """
    if host is None:
        host = os.getenv("GATEWAY_HOST", gateway_settings.gateway_base_url.split("://")[1].split(":")[0] if "://" in gateway_settings.gateway_base_url else "0.0.0.0")
    
    if port is None:
        port = int(os.getenv("GATEWAY_PORT", gateway_settings.gateway_port))
    
    logger.info("=" * 80)
    logger.info(f"{config.name} v{config.version}")
    logger.info("=" * 80)
    logger.info(f"Listening on {host}:{port}")
    logger.info(f"Transport: {transport}")
    logger.info(f"Backends: {list(config.backends.keys())}")
    logger.info(f"Cache: max_size={config.cache.max_size}, ttl={config.cache.ttl_seconds}s")
    logger.info("=" * 80)
    
    # Run server
    if transport == "http":
        import json
        import httpx
        import uvicorn
        from starlette.applications import Starlette
        from starlette.routing import Route
        from starlette.responses import JSONResponse
        from starlette.requests import Request
        import subprocess
        import asyncio
        
        # OAuth discovery endpoint handlers
        async def oauth_protected_resource(request: Request):
            """Serve /.well-known/oauth-protected-resource as HTTP endpoint"""
            metadata = {
                "authorization_servers": [config.gateway.gateway_base_url],
                "scopes_supported": ["openid", "offline_access"],
                "bearer_methods_supported": ["header"]
            }
            return JSONResponse(metadata)
        
        async def oauth_authorization_server(request: Request):
            """Serve /.well-known/oauth-authorization-server"""
            # Fetch Okta's discovery and modify it
            try:
                async with httpx.AsyncClient() as client:
                    okta_url = f"https://{config.gateway.okta_domain}/.well-known/oauth-authorization-server"
                    response = await client.get(okta_url, timeout=10)
                    okta_discovery = response.json()
            except Exception as e:
                logger.error(f"Failed to fetch Okta discovery: {e}")
                okta_discovery = {
                    "issuer": f"https://{config.gateway.okta_domain}",
                    "authorization_endpoint": f"https://{config.gateway.okta_domain}/oauth2/v1/authorize",
                    "token_endpoint": f"https://{config.gateway.okta_domain}/oauth2/v1/token",
                    "jwks_uri": f"https://{config.gateway.okta_domain}/oauth2/v1/keys",
                }
            
            # Override endpoints to point to GATEWAY (Backend-for-Frontend pattern)
            # Authorization happens at Okta, but token exchange happens at gateway
            okta_discovery["authorization_endpoint"] = f"https://{config.gateway.okta_domain}/oauth2/v1/authorize"
            okta_discovery["token_endpoint"] = f"{config.gateway.gateway_base_url}/oauth2/v1/token"  # Gateway endpoint!
            okta_discovery["scopes_supported"] = ["openid", "offline_access"]
            
            # Add gateway registration endpoint
            okta_discovery["registration_endpoint"] = f"{config.gateway.gateway_base_url}/.well-known/oauth/registration"
            return JSONResponse(okta_discovery)
        
        async def oauth_registration(request: Request):
            """
            Serve /.well-known/oauth/registration - Dynamic Client Registration (RFC 7591).
            
            Supports both:
            1. GET - retrieve existing client credentials for an agent
            2. POST - register a new client (simplified DCR)
            """
            if request.method == "GET":
                # Get agent name from query param or header
                agent_name = request.query_params.get("agent")
                if not agent_name:
                    agent_name = request.headers.get("x-mcp-agent")
                
                # Return credentials for agent (minimal public info only)
                if agent_name and agent_name in config.agents:
                    agent_config = config.agents[agent_name]
                    registration_info = {
                        "client_id": agent_config.client_id,
                        "redirect_uris": ["http://localhost:*/callback", "http://127.0.0.1:*/callback", "https://vscode.dev/redirect"],
                        "response_types": ["code", "id_token", "token"],
                        "grant_types": ["authorization_code", "refresh_token"],
                        "token_endpoint_auth_method": "client_secret_basic",
                        "application_type": "web"
                    }
                    return JSONResponse(registration_info)
                else:
                    # Return all available agents
                    available_agents = {}
                    for name, cfg in config.agents.items():
                        available_agents[name] = {
                            "client_id": cfg.client_id,
                            "agent_id": cfg.agent_id,
                            "enabled": cfg.enabled
                        }
                    registration_info = {
                        "status": "available_agents",
                        "agents": available_agents,
                        "note": "Pass ?agent=<agent_name> or X-MCP-Agent header to get credentials for specific agent"
                    }
                    return JSONResponse(registration_info)
            
            elif request.method == "POST":
                # Dynamic Client Registration (RFC 7591)
                try:
                    # Try to parse body, but it might be empty
                    body_bytes = await request.body()
                    logger.info(f"DCR POST body (full): {body_bytes.decode()}")  # Log full body
                    
                    if body_bytes:
                        body = json.loads(body_bytes)
                    else:
                        body = {}
                    
                    # Extract client metadata from request
                    requested_redirect_uris = body.get("redirect_uris", [])
                    client_name = body.get("client_name", "MCP Client")
                    token_endpoint_auth_method = body.get("token_endpoint_auth_method", "client_secret_basic")
                    application_type = body.get("application_type", "web")
                    grant_types = body.get("grant_types", ["authorization_code", "refresh_token"])
                    response_types = body.get("response_types", ["code"])
                    
                    # Get agent name from header or default to "claude-code"
                    agent_name = request.headers.get("x-mcp-agent", "claude-code")
                    logger.info(f"DCR request for agent: {agent_name}")
                    
                    # Return client credentials for this agent
                    if agent_name in config.agents:
                        agent_config = config.agents[agent_name]
                        logger.info(f"Found agent config for {agent_name}")
                        
                        # Filter redirect_uris to only include known valid ones
                        # These must match what's registered in the Okta app
                        # (trailing slashes are normalized for comparison)
                        valid_redirect_uris = {
                            "https://insiders.vscode.dev/redirect",
                            "https://vscode.dev/redirect",
                            "http://127.0.0.1/",
                            "http://127.0.0.1:33418",
                            "http://127.0.0.1:33418/",
                            "http://localhost:3000",
                        }
                        
                        # Filter requested URIs to valid ones (no normalization needed if all are in Okta)
                        filtered_redirect_uris = [uri for uri in requested_redirect_uris if uri in valid_redirect_uris]
                        
                        if not filtered_redirect_uris:
                            # If none match, use defaults
                            filtered_redirect_uris = ["https://vscode.dev/redirect", "http://127.0.0.1:33418"]
                        
                        logger.info(f"Requested redirect_uris: {requested_redirect_uris}")
                        logger.info(f"Filtered redirect_uris: {filtered_redirect_uris}")
                        
                        # Return RFC 7591 DCR response - echo back client's settings
                        # For public clients (Copilot), use "none" and don't include client_secret
                        # Copilot will use PKCE (code_challenge) for secure token exchange
                        response_data = {
                            "client_id": agent_config.client_id,
                            "client_id_issued_at": int(__import__('time').time()),
                            "client_secret_expires_at": 0,
                            "redirect_uris": filtered_redirect_uris,
                            "response_types": response_types,
                            "grant_types": grant_types,
                            "token_endpoint_auth_method": "none",  # Public client - PKCE instead
                            "application_type": application_type
                        }
                        
                        # Do NOT include client_secret - Copilot is a public client using PKCE
                        
                        logger.info(f"Returning DCR response: client_id={response_data['client_id']}, auth_method=none (PKCE), app_type={application_type}, redirect_uris={filtered_redirect_uris}")
                        return JSONResponse(response_data, status_code=201)
                    else:
                        logger.warning(f"Agent '{agent_name}' not found. Available: {list(config.agents.keys())}")
                        return JSONResponse(
                            {"error": "invalid_request", "error_description": f"Agent '{agent_name}' not found"},
                            status_code=400
                        )
                except json.JSONDecodeError as e:
                    logger.warning(f"DCR JSON decode error: {e}")
                    # Return fallback DCR response (body might not be JSON)
                    agent_name = request.headers.get("x-mcp-agent", "claude-code")
                    if agent_name in config.agents:
                        agent_config = config.agents[agent_name]
                        # Use known valid redirect URIs for fallback
                        response_data = {
                            "client_id": agent_config.client_id,
                            "client_id_issued_at": int(__import__('time').time()),
                            "client_secret_expires_at": 0,
                            "redirect_uris": ["https://vscode.dev/redirect", "http://127.0.0.1:33418"],
                            "response_types": ["code"],
                            "grant_types": ["authorization_code", "refresh_token"],
                            "token_endpoint_auth_method": "none",  # Public client - PKCE
                            "application_type": "native"  # Native app
                        }
                        # Do NOT include client_secret - public client uses PKCE
                        return JSONResponse(response_data, status_code=201)
                    return JSONResponse(
                        {"error": "invalid_request", "error_description": "Invalid JSON"},
                        status_code=400
                    )
                except Exception as e:
                    logger.error(f"DCR error: {e}", exc_info=True)
                    return JSONResponse(
                        {"error": "invalid_request", "error_description": str(e)},
                        status_code=400
                    )
            
            return JSONResponse({"error": "Method not allowed"}, status_code=405)
        
        # MCP proxy handler - routes MCP protocol requests through the proxy handler
        async def mcp_proxy(request: Request):
            """
            Proxy MCP protocol requests to backend MCP servers via the gateway.
            
            Implements MCP streamable HTTP transport:
            - POST / with JSON-RPC requests
            - GET / for SSE streaming responses (with mcp-session-id header)
            """
            # Extract path from route params or URL path
            request_path = request.path_params.get("path", "")
            if not request_path:
                request_path = request.url.path
            
            logger.debug(f"MCP Proxy: {request.method} {request_path}, auth: {request.headers.get('authorization')}")
            
            if request.method == "POST":
                try:
                    body_bytes = await request.body()
                    body_text = body_bytes.decode()
                    body = json.loads(body_text)
                    
                    # Validate JSON-RPC 2.0 format
                    if not isinstance(body, dict):
                        logger.warning("Invalid JSON-RPC: request is not a JSON object")
                        return JSONResponse({
                            "jsonrpc": "2.0",
                            "error": {
                                "code": -32600,
                                "message": "Invalid Request: must be a JSON object"
                            }
                        }, status_code=400)
                    
                    if body.get("jsonrpc") != "2.0":
                        logger.warning(f"Invalid JSON-RPC: expected jsonrpc 2.0, got {body.get('jsonrpc')}")
                        return JSONResponse({
                            "jsonrpc": "2.0",
                            "error": {
                                "code": -32600,
                                "message": "Invalid Request: jsonrpc must be 2.0"
                            }
                        }, status_code=400)
                    
                    # For requests (not notifications), must have an ID
                    request_id = body.get("id")
                    is_notification = request_id is None
                    
                    method = body.get("method")
                    if not method:
                        logger.warning("Invalid JSON-RPC: missing method")
                        error_response = {
                            "jsonrpc": "2.0",
                            "error": {
                                "code": -32600,
                                "message": "Invalid Request: missing method"
                            }
                        }
                        if request_id is not None:
                            error_response["id"] = request_id
                        return JSONResponse(error_response, status_code=400)
                    
                    logger.info(f"MCP POST request: method={method}, id={request_id}, is_notification={is_notification}")
                    
                    # Handle gateway protocol methods (don't need auth, don't forward to backend)
                    if method == "initialize":
                        logger.info("Handling initialize request (no auth required)")
                        return JSONResponse({
                            "jsonrpc": "2.0",
                            "id": body.get("id"),
                            "result": {
                                "protocolVersion": "2025-11-25",
                                "capabilities": {
                                    "tools": {},
                                    "resources": {
                                        "subscribe": False
                                    },
                                    "prompts": {},
                                    "logging": {}
                                },
                                "serverInfo": {
                                    "name": config.name,
                                    "version": config.version,
                                    "icons": [get_gateway_icon()]
                                }
                            }
                        })
                    
                    elif method == "initialized":
                        # Per JSON-RPC 2.0 spec: notifications MUST NOT include an ID
                        # If this is a notification (no id), don't send a response
                        request_id = body.get("id")
                        if request_id is None:
                            logger.info("Client sent initialized notification (no response required)")
                            return JSONResponse({})
                        else:
                            logger.info("Client confirmed initialization (responding to request)")
                            return JSONResponse({
                                "jsonrpc": "2.0",
                                "id": request_id
                            })
                    
                    elif method == "shutdown":
                        logger.info("Shutdown requested")
                        return JSONResponse({
                            "jsonrpc": "2.0",
                            "id": body.get("id")
                        })
                    
                    # Protocol/logging methods that don't require auth
                    elif method in ["logging/setLevel", "notifications/initialized", "notifications/message"]:
                        logger.info(f"Protocol method {method} (no auth required)")
                        
                        # Per JSON-RPC 2.0 spec: notifications MUST NOT include an ID
                        # If this is a notification (no id), don't send a response
                        request_id = body.get("id")
                        if request_id is None:
                            logger.debug(f"Received notification {method} - not sending response")
                            # Return empty response (caller won't use it since it's a notification)
                            return JSONResponse({})
                        else:
                            # This is a request (has ID), so respond
                            return JSONResponse({
                                "jsonrpc": "2.0",
                                "id": request_id
                            })
                    
                    # Discovery methods - require auth to forward to backend
                    if method in ["tools/list", "resources/list", "prompts/list"]:
                        auth_header = request.headers.get("authorization")
                        if not auth_header:
                            # Only return 401 for tools/list to trigger OAuth ONCE
                            if method == "tools/list":
                                logger.info(f"Discovery request {method} without auth, returning 401 to trigger OAuth")
                                return JSONResponse(
                                    {"error": "Unauthorized"},
                                    status_code=401,
                                    headers={
                                        "WWW-Authenticate": f'Bearer realm="{config.gateway.gateway_base_url}", error="invalid_token"'
                                    }
                                )
                            else:
                                # For other discovery methods, return empty results (client will retry after OAuth)
                                logger.info(f"Discovery request {method} without auth, returning empty result")
                                if method == "resources/list":
                                    return JSONResponse({
                                        "jsonrpc": "2.0",
                                        "id": body.get("id"),
                                        "result": {"resources": []}
                                    })
                                elif method == "prompts/list":
                                    return JSONResponse({
                                        "jsonrpc": "2.0",
                                        "id": body.get("id"),
                                        "result": {"prompts": []}
                                    })
                        
                        logger.info(f"Discovery request: {method} with auth, forwarding to backend")
                        result = await proxy_handler.proxy_request(
                            request_path=f"/{request_path}",
                            method=method,
                            params=body.get("params"),
                            auth_header=auth_header,
                            request_id=body.get("id"),
                            headers=dict(request.headers)
                        )
                        
                        logger.info(f"Backend returned result for {method}: {result}")
                        
                        response = {
                            "jsonrpc": "2.0",
                            "id": body.get("id"),
                        }
                        
                        # The proxy handler already unwraps the "result" field from the MCP response
                        # So result is already the unwrapped data (e.g., {"tools": [...]} for tools/list)
                        # Just use it directly as the response result
                        if isinstance(result, dict) and "error" in result:
                            # If it's an error, use it as-is
                            response["error"] = result["error"]
                        else:
                            # Otherwise, wrap it in "result" for the MCP response
                            response["result"] = result
                        
                        # Log what we're sending back to client
                        if method == "tools/list" and "result" in response:
                            num_tools = len(response["result"].get("tools", []))
                            tool_names = [t.get("name") for t in response["result"].get("tools", [])]
                            logger.info(f"✅ SENDING {num_tools} tools to Copilot: {tool_names}")
                        
                        logger.debug(f"MCP response for {method}: {response}")
                        # Preserve _meta property from request if present
                        response = preserve_meta_in_response(body, response)
                        return JSONResponse(response)
                    
                    # Known MCP methods that don't require special handling
                    # (will be forwarded to backend if auth is provided)
                    known_methods = {
                        # Lifecycle
                        "initialize", "initialized", "shutdown",
                        # Discovery
                        "tools/list", "resources/list", "prompts/list",
                        # Tool/resource/prompt operations
                        "tools/call",
                        "resources/read", "resources/templates/list",
                        "prompts/get", "prompts/list",
                        # Logging/notifications
                        "logging/setLevel",
                        "notifications/initialized", "notifications/message",
                        # Client features
                        "sampling/createMessage",
                        # Utilities
                        "completion/complete"
                    }
                    
                    # Check if method is known (for logging/debugging)
                    if method not in known_methods:
                        logger.debug(f"Unknown method '{method}' - will forward to backend if authenticated")
                    
                    # For all other methods (actual tool calls, etc.), require auth
                    auth_header = request.headers.get("authorization")
                    if not auth_header:
                        logger.info(f"Auth-required method {method} has no auth header, returning 401")
                        return JSONResponse(
                            {"error": "Unauthorized"},
                            status_code=401,
                            headers={
                                "WWW-Authenticate": f'Bearer realm="{config.gateway.gateway_base_url}", error="invalid_token"'
                            }
                        )
                    
                    logger.info(f"Auth-required method: {method}, auth header present, forwarding to backend")
                    
                    # Use proxy handler to process the request
                    # The proxy handler will handle auth, backend routing, etc.
                    result = await proxy_handler.proxy_request(
                        request_path=f"/{request_path}",  # Include path for routing
                        method=method,
                        params=body.get("params"),
                        auth_header=auth_header,
                        request_id=body.get("id"),
                        headers=dict(request.headers)
                    )
                    
                    logger.info(f"Proxy result for {method}: {len(json.dumps(result))} bytes")
                    
                    # Return response
                    response = {
                        "jsonrpc": "2.0",
                        "id": body.get("id"),
                    }
                    if "result" in result:
                        response["result"] = result["result"]
                    elif "error" in result:
                        response["error"] = result["error"]
                    else:
                        response["result"] = result
                    
                    # Preserve _meta property from request if present
                    response = preserve_meta_in_response(body, response)
                    return JSONResponse(response)
                except json.JSONDecodeError as e:
                    logger.error(f"JSON parse error: {e}")
                    return JSONResponse({
                        "jsonrpc": "2.0",
                        "error": {
                            "code": -32700,
                            "message": "Parse error"
                        }
                    }, status_code=400)
                except Exception as e:
                    logger.error(f"Error handling MCP request: {e}", exc_info=True)
                    return JSONResponse({
                        "jsonrpc": "2.0",
                        "error": {
                            "code": -32603,
                            "message": "Internal error"
                        }
                    }, status_code=500)
            elif request.method == "GET":
                # SSE streaming endpoint
                # Not implemented yet
                return JSONResponse({
                    "error": "SSE streaming not yet implemented"
                }, status_code=501)
            else:
                return JSONResponse({"error": "Method not allowed"}, status_code=405)
        
        async def oauth_token_endpoint(request: Request):
            """
            Backend-for-Frontend (BFF) token exchange endpoint.
            
            Copilot sends auth code + PKCE verifier here.
            Gateway exchanges it with Okta using client_secret_basic (confidential client).
            Returns ID token to Copilot.
            """
            # Parse request body - could be JSON or form-encoded
            try:
                if request.headers.get("content-type", "").startswith("application/x-www-form-urlencoded"):
                    body = dict(await request.form())
                else:
                    body = await request.json()
            except:
                body = dict(request.query_params)
            
            grant_type = body.get("grant_type")
            code = body.get("code")
            code_verifier = body.get("code_verifier")
            client_id = body.get("client_id")
            redirect_uri = body.get("redirect_uri")
            refresh_token = body.get("refresh_token")
            
            logger.info(f"Token request: grant_type={grant_type}, client_id={client_id}, redirect_uri={redirect_uri}")
            
            # Handle refresh token requests
            if grant_type == "refresh_token":
                logger.info(f"Refresh token request received for client_id={client_id}")
                
                if not refresh_token or not client_id:
                    logger.warning(f"Refresh token request missing required fields: refresh_token={bool(refresh_token)}, client_id={client_id}")
                    return JSONResponse(
                        {"error": "invalid_request"},
                        status_code=400
                    )
                
                # Find agent config by client_id
                agent_config = None
                agent_name = None
                for agent_name_iter, agent in config.agents.items():
                    if agent.client_id == client_id:
                        agent_config = agent
                        agent_name = agent_name_iter
                        break
                
                if not agent_config:
                    logger.warning(f"Unknown client_id in refresh token request: {client_id}")
                    return JSONResponse(
                        {"error": "invalid_client"},
                        status_code=401
                    )
                
                try:
                    # Forward refresh token request to Okta
                    async with httpx.AsyncClient() as client:
                        okta_token_url = f"https://{config.gateway.okta_domain}/oauth2/v1/token"
                        
                        token_data = {
                            "grant_type": "refresh_token",
                            "refresh_token": refresh_token,
                        }
                        
                        # Use client_secret_basic auth
                        auth = (client_id, agent_config.client_secret)
                        
                        logger.info(f"Refreshing token for client_id={client_id}")
                        okta_response = await client.post(
                            okta_token_url,
                            data=token_data,
                            auth=auth,
                            timeout=10
                        )
                        
                        if okta_response.status_code != 200:
                            logger.error(f"Okta refresh token failed: {okta_response.status_code} - {okta_response.text}")
                            return JSONResponse(
                                {"error": "invalid_grant"},
                                status_code=400
                            )
                        
                        refresh_response = okta_response.json()
                        logger.info(f"Successfully refreshed token for {agent_name}")
                        
                        # Extract tokens from Okta response
                        id_token = refresh_response.get("id_token")
                        new_refresh_token = refresh_response.get("refresh_token")
                        expires_in = refresh_response.get("expires_in", 3600)
                        
                        logger.info(f"Refresh token response from Okta:")
                        logger.info(f"  - ID token: {'present' if id_token else 'MISSING'}")
                        logger.info(f"  - Refresh token: {'present' if new_refresh_token else 'not included'}")
                        logger.info(f"  - Expires in: {expires_in}s")
                        
                        # Return new tokens to client
                        response_to_client = {
                            "access_token": id_token,  # Return ID token as bearer
                            "id_token": id_token,
                            "token_type": "Bearer",
                            "expires_in": expires_in,
                        }
                        
                        # Include new refresh token if provided
                        if new_refresh_token:
                            response_to_client["refresh_token"] = new_refresh_token
                            logger.info(f"Returning new refresh token to client for {agent_name}")
                        else:
                            logger.info(f"No new refresh token from Okta, client will keep existing one")
                        
                        logger.info(f"Returning refreshed tokens to client for {agent_name}")
                        return JSONResponse(response_to_client)
                
                except Exception as e:
                    logger.error(f"Refresh token error: {e}")
                    return JSONResponse(
                        {"error": "server_error"},
                        status_code=500
                    )
            
            # Handle authorization code exchange
            if grant_type != "authorization_code":
                return JSONResponse(
                    {"error": "unsupported_grant_type"},
                    status_code=400
                )
            
            if not code or not client_id:
                return JSONResponse(
                    {"error": "invalid_request"},
                    status_code=400
                )
            
            # Find agent config - first try X-MCP-Agent header, then fallback to client_id lookup
            agent_config = None
            agent_name = None
            
            # Try to get agent name from X-MCP-Agent header
            if request.headers.get("x-mcp-agent"):
                agent_name = request.headers.get("x-mcp-agent")
                if agent_name in config.agents:
                    agent_config = config.agents[agent_name]
                    logger.info(f"Found agent from X-MCP-Agent header: {agent_name}")
            
            # If not found via header, look up by client_id
            if not agent_config:
                for agent_name_iter, agent in config.agents.items():
                    if agent.client_id == client_id:
                        agent_config = agent
                        agent_name = agent_name_iter
                        break
                if agent_config:
                    logger.info(f"Found agent by client_id: {agent_name}")
            
            if not agent_config:
                logger.warning(f"Unknown client_id in token request: {client_id}")
                return JSONResponse(
                    {"error": "invalid_client"},
                    status_code=401
                )
            
            try:
                # Exchange auth code with Okta using client_secret_basic
                async with httpx.AsyncClient() as client:
                    okta_token_url = f"https://{config.gateway.okta_domain}/oauth2/v1/token"
                    
                    # Build the token request to Okta
                    # When using Basic Auth (client_id:client_secret), don't include them in body
                    token_data = {
                        "grant_type": "authorization_code",
                        "code": code,
                        "redirect_uri": redirect_uri,
                    }
                    
                    # Add code_verifier for PKCE (if provided by Copilot)
                    if code_verifier:
                        token_data["code_verifier"] = code_verifier
                    
                    # Use client_secret_basic auth (gateway is confidential client)
                    auth = (client_id, agent_config.client_secret)
                    
                    logger.info(f"Exchanging auth code with Okta for client_id={client_id}")
                    okta_response = await client.post(
                        okta_token_url,
                        data=token_data,
                        auth=auth,
                        timeout=10
                    )
                    
                    if okta_response.status_code != 200:
                        logger.error(f"Okta token exchange failed: {okta_response.status_code} - {okta_response.text}")
                        return JSONResponse(
                            {"error": "invalid_grant"},
                            status_code=400
                        )
                    
                    token_response = okta_response.json()
                    logger.info(f"Successfully exchanged auth code for token")
                    
                    # Verify we got both ID token and access token from Okta
                    id_token = token_response.get("id_token")
                    access_token = token_response.get("access_token")
                    
                    if not id_token:
                        logger.error("No id_token in Okta response! Okta returned:", token_response.keys())
                        return JSONResponse(
                            {"error": "server_error", "error_description": "No id_token from Okta"},
                            status_code=500
                        )
                    
                    if not access_token:
                        logger.error("No access_token in Okta response! Required for ID-JAG exchange. Okta returned:", token_response.keys())
                        return JSONResponse(
                            {"error": "server_error", "error_description": "No access_token from Okta"},
                            status_code=500
                        )
                    
                    # Log both tokens' claims for debugging
                    try:
                        from jose import jwt
                        id_claims = jwt.get_unverified_claims(id_token)
                        access_claims = jwt.get_unverified_claims(access_token)
                        logger.info(f"ID Token claims: iss={id_claims.get('iss')}, aud={id_claims.get('aud')}, sub={id_claims.get('sub')}, token_use={id_claims.get('token_use')}")
                        logger.info(f"Access Token claims: iss={access_claims.get('iss')}, aud={access_claims.get('aud')}, cid={access_claims.get('cid')}, sub={access_claims.get('sub')}, token_use={access_claims.get('token_use')}, scope={access_claims.get('scope')}")
                        # Log full access token payload for debugging
                        logger.debug(f"Full Access Token payload: {access_claims}")
                    except Exception as e:
                        logger.warning(f"Could not decode token claims: {e}")
                    
                    # Return BOTH tokens to client
                    # - id_token: For client authentication/identification (also can be used as bearer token for MCP)
                    # - access_token: Use ID token as the bearer token for RFC8693 ID-JAG token exchange
                    # RFC8693 requires subject_token to be an ID token, not an access token
                    
                    # Log which token we're returning as access_token
                    try:
                        id_token_claims = jwt.get_unverified_claims(id_token)
                        access_token_claims = jwt.get_unverified_claims(access_token)
                        logger.info(f"OAuth Response Tokens:")
                        logger.info(f"  id_token claims: aud={id_token_claims.get('aud')}, sub={id_token_claims.get('sub')}, token_use={id_token_claims.get('token_use')}")
                        logger.info(f"  Okta access_token claims: aud={access_token_claims.get('aud')}, sub={access_token_claims.get('sub')}, cid={access_token_claims.get('cid')}")
                        logger.info(f"  >>> RETURNING id_token in access_token field for RFC8693 ID-JAG <<<")
                    except Exception as e:
                        logger.debug(f"Could not decode token claims: {e}")
                    
                    response_to_client = {
                        "id_token": id_token,
                        "access_token": id_token,  # Return ID token as bearer token for MCP (RFC8693 requires this)
                        "token_type": "Bearer",
                        "expires_in": token_response.get("expires_in", 3600),
                    }
                    
                    # Include refresh token if present
                    if token_response.get("refresh_token"):
                        response_to_client["refresh_token"] = token_response.get("refresh_token")
                    
                    logger.info(f"Returning both id_token and access_token to client")
                    return JSONResponse(response_to_client)
                    
            except Exception as e:
                logger.error(f"Token exchange error: {e}")
                return JSONResponse(
                    {"error": "server_error"},
                    status_code=500
                )
        
        # Routes for discovery endpoints and MCP proxy
        # Order matters: specific routes first, then catch-all
        routes = [
            # Admin API routes (secured with JWT)
            Route("/api/admin/login", admin_routes.admin_login, methods=["POST"]),
            Route("/api/admin/agents", admin_routes.list_agents, methods=["GET"]),
            Route("/api/admin/agents", admin_routes.create_agent, methods=["POST"]),
            Route("/api/admin/agents/{name}", admin_routes.update_agent, methods=["PUT"]),
            Route("/api/admin/agents/{name}", admin_routes.delete_agent, methods=["DELETE"]),
            Route("/api/admin/backends", admin_routes.list_backends, methods=["GET"]),
            Route("/api/admin/backends", admin_routes.create_backend, methods=["POST"]),
            Route("/api/admin/backends/{name}", admin_routes.update_backend, methods=["PUT"]),
            Route("/api/admin/backends/{name}", admin_routes.delete_backend, methods=["DELETE"]),
            # OAuth and MCP routes
            Route("/.well-known/oauth-protected-resource", oauth_protected_resource, methods=["GET"]),
            Route("/.well-known/oauth-authorization-server", oauth_authorization_server, methods=["GET"]),
            Route("/.well-known/oauth/registration", oauth_registration, methods=["GET", "POST"]),
            Route("/oauth2/v1/token", oauth_token_endpoint, methods=["POST"]),
            Route("/", mcp_proxy, methods=["GET", "POST"]),
            Route("/{path:path}", mcp_proxy, methods=["GET", "POST"]),  # Catch-all for /employees, /hr, etc.
        ]
        
        # Create Starlette app
        app = Starlette(routes=routes)
        
        # Run with uvicorn
        uvicorn.run(
            app,
            host=host,
            port=port,
            log_level="info"
        )
    else:
        mcp.run(
            transport=transport,
            host=host,
            port=port
        )


if __name__ == "__main__":
    # For local development: python -m okta_agent_proxy.main
    import sys
    
    transport = "http" if "http" in sys.argv else "stdio"
    run(transport=transport)

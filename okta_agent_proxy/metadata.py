"""
Protected Resource Metadata Endpoint (RFC9728)

Implements the OAuth 2.0 Protected Resource Metadata specification (RFC9728).

The endpoint at /.well-known/oauth-protected-resource tells clients:
1. Where the authorization server (Okta) is located
2. What documentation is available
3. What scopes are needed

Clients then query the Okta authorization server directly for RFC8414 
OAuth discovery metadata (token endpoints, JWKS URIs, etc.).
"""

import os
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)


def get_protected_resource_metadata() -> Dict[str, Any]:
    """
    Generate Protected Resource Metadata (RFC9728).
    
    This tells clients where to find the authorization server (Okta)
    and how to authenticate.
    
    Returns:
        Metadata dict following RFC9728 format
    """
    okta_domain = os.getenv("OKTA_DOMAIN")
    if not okta_domain:
        logger.warning("OKTA_DOMAIN environment variable is not set")
        raise ValueError("OKTA_DOMAIN is required for Protected Resource Metadata")
    
    okta_issuer = f"https://{okta_domain}"
    gateway_base_url = os.getenv("GATEWAY_BASE_URL", "http://localhost:8000")
    
    metadata = {
        # RFC9728 required fields
        "resource_documentation_uri": f"{gateway_base_url}/docs",
        "authorization_servers": [
            okta_issuer  # e.g., https://dev-12345.okta.com
        ],
        
        # Additional helpful metadata
        "resource_identification": {
            "name": "Okta MCP Agent Proxy",
            "description": "Secure gateway for MCP servers with Okta OAuth2 protection"
        },
        
        # Recommended scopes
        "scopes_supported": [
            "mcp:read",      # Read access to MCP resources
            "mcp:write",     # Write access (tool calls)
            "offline_access" # Refresh token
        ],
        
        # Token endpoint information
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post"
        ],
        
        # Authorization methods
        "auth_methods": [
            "oauth2",  # This is an OAuth2-protected resource
        ],
        
        # Indicate that all tools require authentication
        "tools_require_auth": True,
        "resources_require_auth": True,
    }
    
    logger.debug(f"Protected Resource Metadata: {metadata}")
    return metadata


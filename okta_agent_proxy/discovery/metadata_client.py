"""
Target MCP Metadata Discovery Client

Implements RFC 9728 Protected Resource Metadata discovery.

Supports two patterns for ID-JAG cross-app access:

1. Static Pattern (configured):
   Gateway has pre-configured auth server details
   Faster, simpler, no discovery needed

2. Dynamic Pattern (discovered):
   Gateway queries target's /.well-known/mcp-protected-resource endpoint
   Extracts authorization server details dynamically
   More flexible, works with any compliant target
"""

import logging
import httpx
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
from cachetools import TTLCache

logger = logging.getLogger(__name__)

# Cache for discovered metadata
# Key: target_url, TTL: 3600 seconds (1 hour)
_metadata_cache: TTLCache = TTLCache(maxsize=1000, ttl=3600)


class MetadataDiscoveryClient:
    """
    Discovers Protected Resource Metadata from target MCP servers.
    
    Per RFC 9728:
    https://datatracker.ietf.org/doc/html/draft-ietf-oauth-protected-resource-metadata-00
    
    Endpoint: https://target-mcp.example.com/.well-known/mcp-protected-resource
    """
    
    def __init__(self, timeout: float = 10.0):
        """
        Initialize discovery client.
        
        Args:
            timeout: HTTP request timeout in seconds
        """
        self.timeout = timeout
        logger.info("MetadataDiscoveryClient initialized")
    
    async def discover_metadata(
        self,
        target_url: str,
        force_refresh: bool = False
    ) -> Optional[Dict[str, Any]]:
        """
        Discover protected resource metadata from target MCP server.
        
        Queries: https://target_url/.well-known/mcp-protected-resource
        
        Args:
            target_url: Base URL of target MCP server (e.g., https://example.com)
            force_refresh: Skip cache and fetch fresh metadata
            
        Returns:
            Metadata dict with authorization_servers, scopes, etc.
            Returns None if discovery fails
        """
        # Normalize URL
        target_url = target_url.rstrip("/")
        
        # Check cache first
        if not force_refresh and target_url in _metadata_cache:
            logger.debug(f"Using cached metadata for {target_url}")
            return _metadata_cache[target_url]
        
        # Build well-known URL
        well_known_url = f"{target_url}/.well-known/mcp-protected-resource"
        
        try:
            logger.debug(f"Discovering metadata from {well_known_url}")
            
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    well_known_url,
                    timeout=self.timeout,
                    headers={"Accept": "application/json"}
                )
                response.raise_for_status()
                
                metadata = response.json()
                logger.debug(f"Discovered metadata for {target_url}: {metadata}")
                
                # Cache the metadata
                _metadata_cache[target_url] = metadata
                
                return metadata
        
        except httpx.HTTPStatusError as e:
            logger.warning(
                f"HTTP error discovering metadata for {target_url}: "
                f"{e.response.status_code} - {e.response.text}"
            )
            return None
        
        except httpx.RequestError as e:
            logger.warning(f"Network error discovering metadata for {target_url}: {e}")
            return None
        
        except Exception as e:
            logger.warning(
                f"Error discovering metadata for {target_url}: {e}",
                exc_info=True
            )
            return None
    
    async def extract_auth_server_details(
        self,
        target_url: str,
        force_refresh: bool = False
    ) -> Optional[Dict[str, str]]:
        """
        Extract authorization server details from discovered metadata.
        
        Looks for:
        - authorization_servers (array of issuer URLs)
        - authorization_server_metadata (dict with token_endpoint, etc.)
        
        Returns mapping that can be used for ID-JAG exchange.
        
        Args:
            target_url: Base URL of target MCP server
            force_refresh: Skip cache and fetch fresh metadata
            
        Returns:
            Dict with keys: target_authorization_server, target_token_endpoint
            Returns None if extraction fails
        """
        metadata = await self.discover_metadata(target_url, force_refresh)
        
        if not metadata:
            logger.error(f"Could not discover metadata for {target_url}")
            return None
        
        try:
            # Extract authorization server details
            auth_servers = metadata.get("authorization_servers", [])
            auth_server_metadata = metadata.get("authorization_server_metadata", {})
            
            if not auth_servers:
                logger.error(f"No authorization_servers in metadata for {target_url}")
                return None
            
            # Use first authorization server
            target_authorization_server = auth_servers[0]
            
            # Extract token endpoint
            token_endpoint = auth_server_metadata.get("token_endpoint")
            
            if not token_endpoint:
                # Build from issuer if not provided
                if target_authorization_server:
                    token_endpoint = f"{target_authorization_server}/oauth2/v1/token"
            
            result = {
                "target_authorization_server": target_authorization_server,
                "target_token_endpoint": token_endpoint,
                "full_metadata": metadata
            }
            
            logger.info(
                f"Extracted auth server details for {target_url}: "
                f"{target_authorization_server}"
            )
            
            return result
        
        except Exception as e:
            logger.error(
                f"Error extracting auth server details from metadata: {e}",
                exc_info=True
            )
            return None
    
    def clear_cache(self, target_url: Optional[str] = None):
        """
        Clear cached metadata.
        
        Args:
            target_url: Clear cache for specific URL, or None to clear all
        """
        if target_url:
            target_url = target_url.rstrip("/")
            if target_url in _metadata_cache:
                del _metadata_cache[target_url]
                logger.debug(f"Cleared cache for {target_url}")
        else:
            _metadata_cache.clear()
            logger.debug("Cleared all metadata cache")


# Global discovery client instance
_discovery_client: Optional[MetadataDiscoveryClient] = None


def get_discovery_client() -> MetadataDiscoveryClient:
    """Get or create global discovery client instance."""
    global _discovery_client
    if _discovery_client is None:
        _discovery_client = MetadataDiscoveryClient()
    return _discovery_client


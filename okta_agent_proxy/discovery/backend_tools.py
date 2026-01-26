"""
Dynamic tool registration from backend servers.

This module introspects backend MCP servers and registers their tools
and resources on the gateway dynamically, making the gateway transparent.
"""

import logging
import httpx
import json
from typing import Dict, Any, Optional, List

logger = logging.getLogger(__name__)


async def discover_backend_tools(backend_url: str, auth_headers: Dict[str, str]) -> List[Dict[str, Any]]:
    """
    Discover tools from a backend MCP server via tools/list.
    
    Args:
        backend_url: Backend MCP server URL
        auth_headers: Authentication headers
    
    Returns:
        List of tool definitions or empty list if discovery fails
    """
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                backend_url,
                json={
                    "jsonrpc": "2.0",
                    "id": "discover",
                    "method": "tools/list",
                    "params": {}
                },
                headers={
                    **auth_headers,
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                timeout=10.0
            )
            
            if response.status_code == 200:
                result = response.json()
                tools = result.get("result", {}).get("tools", [])
                logger.info(f"Discovered {len(tools)} tools from {backend_url}")
                return tools
            else:
                logger.warning(f"Failed to discover tools: {response.status_code}")
                return []
    
    except Exception as e:
        logger.error(f"Error discovering backend tools: {e}")
        return []


async def discover_backend_resources(backend_url: str, auth_headers: Dict[str, str]) -> List[Dict[str, Any]]:
    """
    Discover resources from a backend MCP server via resources/list.
    """
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                backend_url,
                json={
                    "jsonrpc": "2.0",
                    "id": "discover",
                    "method": "resources/list",
                    "params": {}
                },
                headers={
                    **auth_headers,
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                timeout=10.0
            )
            
            if response.status_code == 200:
                result = response.json()
                resources = result.get("result", {}).get("resources", [])
                logger.info(f"Discovered {len(resources)} resources from {backend_url}")
                return resources
            else:
                logger.warning(f"Failed to discover resources: {response.status_code}")
                return []
    
    except Exception as e:
        logger.error(f"Error discovering backend resources: {e}")
        return []


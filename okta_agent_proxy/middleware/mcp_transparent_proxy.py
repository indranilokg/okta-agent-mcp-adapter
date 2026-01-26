"""
Transparent MCP Proxy - Request Interceptor

Detects MCP protocol requests (tools/list, resources/list, etc.) and forwards them
directly to the backend without invoking gateway tools. Makes the gateway transparent.

Implementation Note:
This is handled at the MCP protocol level by detecting method names that should
be forwarded to backend, rather than trying to intercept HTTP middleware.
"""

import logging
import json
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

# MCP protocol methods that should be forwarded to backend
# (as opposed to gateway tools)
BACKEND_PROTOCOL_METHODS = {
    "tools/list",
    "tools/call",
    "resources/list",
    "resources/read",
    "prompts/list",
    "prompts/get",
    "completion/complete",
    "sampling/create_message",
    "roots/list",
}


def should_forward_to_backend(method: str) -> bool:
    """Check if an MCP method should be forwarded to backend."""
    return method in BACKEND_PROTOCOL_METHODS


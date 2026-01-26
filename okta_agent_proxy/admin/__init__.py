"""
Admin API Module

Provides secure admin endpoints for managing agents and backends.
"""

from okta_agent_proxy.admin.auth import generate_admin_token, verify_admin_token, validate_credentials
from okta_agent_proxy.admin.middleware import require_admin_token, admin_required, extract_admin_token
from okta_agent_proxy.admin.config_manager import ConfigManager
from okta_agent_proxy.admin import routes

__all__ = [
    "generate_admin_token",
    "verify_admin_token", 
    "validate_credentials",
    "require_admin_token",
    "admin_required",
    "extract_admin_token",
    "ConfigManager",
    "routes",
]

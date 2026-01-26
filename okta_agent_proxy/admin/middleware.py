"""
Admin API Middleware

Protects admin endpoints with token authentication.
"""

import logging
from typing import Optional, Callable
from starlette.requests import Request
from starlette.responses import JSONResponse
from functools import wraps
from okta_agent_proxy.admin.auth import verify_admin_token, AdminAuthError

logger = logging.getLogger(__name__)


def extract_admin_token(request: Request) -> Optional[str]:
    """
    Extract admin token from Authorization header.
    
    Args:
        request: Starlette request
    
    Returns:
        Token string or None
    """
    auth_header = request.headers.get("authorization", "")
    
    if not auth_header.startswith("Bearer "):
        return None
    
    return auth_header[7:]  # Remove "Bearer " prefix


async def require_admin_token(request: Request) -> Optional[dict]:
    """
    Middleware to verify admin token.
    
    Args:
        request: Starlette request
    
    Returns:
        Token payload if valid, None otherwise
    """
    token = extract_admin_token(request)
    
    if not token:
        logger.warning(f"Missing admin token: {request.method} {request.url.path}")
        return None
    
    try:
        payload = verify_admin_token(token)
        logger.debug(f"Admin token verified for user: {payload.get('username')}")
        return payload
    except AdminAuthError as e:
        logger.warning(f"Admin token verification failed: {e}")
        return None


def admin_required(func: Callable):
    """
    Decorator to require admin token for route handlers.
    
    Usage:
        @app.post("/api/admin/agents")
        @admin_required
        async def create_agent(request: Request):
            ...
    """
    @wraps(func)
    async def wrapper(request: Request, *args, **kwargs):
        payload = await require_admin_token(request)
        
        if not payload:
            logger.warning(f"Unauthorized admin request: {request.method} {request.url.path}")
            return JSONResponse(
                {
                    "error": "unauthorized",
                    "message": "Missing or invalid admin token"
                },
                status_code=401
            )
        
        # Log admin action
        username = payload.get("username")
        logger.info(f"Admin action by {username}: {request.method} {request.url.path}")
        
        # Add payload to request for use in handler
        request.state.admin_payload = payload
        
        return await func(request, *args, **kwargs)
    
    return wrapper

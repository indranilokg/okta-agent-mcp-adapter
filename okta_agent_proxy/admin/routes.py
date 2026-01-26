"""
Admin API Routes

Provides endpoints for managing agents and backends.
"""

import logging
import json
from starlette.responses import JSONResponse
from starlette.requests import Request
from okta_agent_proxy.admin.middleware import admin_required
from okta_agent_proxy.admin.auth import generate_admin_token, validate_credentials, AdminAuthError
from okta_agent_proxy.admin.config_manager import ConfigManager

logger = logging.getLogger(__name__)

# Global config manager instance
_config_manager: ConfigManager = None


def set_config_manager(config_manager: ConfigManager):
    """Set the global config manager instance."""
    global _config_manager
    _config_manager = config_manager


def get_config_manager() -> ConfigManager:
    """Get the global config manager instance."""
    if _config_manager is None:
        raise RuntimeError("Config manager not initialized")
    return _config_manager


# ============================================================================
# Authentication Routes
# ============================================================================

async def admin_login(request: Request):
    """
    Admin login endpoint.
    
    POST /api/admin/login
    {
        "username": "admin",
        "password": "admin123"
    }
    """
    try:
        body = await request.json()
        username = body.get("username", "").strip()
        password = body.get("password", "")
        
        if not username or not password:
            logger.warning("Login attempt with missing credentials")
            return JSONResponse(
                {
                    "error": "invalid_credentials",
                    "message": "Username and password are required"
                },
                status_code=400
            )
        
        # Validate credentials
        if not validate_credentials(username, password):
            return JSONResponse(
                {
                    "error": "invalid_credentials",
                    "message": "Invalid username or password"
                },
                status_code=401
            )
        
        # Generate token
        token_data = generate_admin_token(username)
        return JSONResponse(token_data)
    
    except Exception as e:
        logger.error(f"Login error: {e}", exc_info=True)
        return JSONResponse(
            {
                "error": "server_error",
                "message": "An error occurred during login"
            },
            status_code=500
        )


# ============================================================================
# Agent Routes
# ============================================================================

@admin_required
async def list_agents(request: Request):
    """GET /api/admin/agents"""
    try:
        manager = get_config_manager()
        agents = manager.get_agents()
        
        # Convert to list format for API
        agents_list = []
        for name, config in agents.items():
            agent = {
                "agent_name": name,
                **config
            }
            agents_list.append(agent)
        
        logger.info(f"Listed {len(agents_list)} agents")
        return JSONResponse({"agents": agents_list})
    
    except Exception as e:
        logger.error(f"Error listing agents: {e}", exc_info=True)
        return JSONResponse(
            {
                "error": "server_error",
                "message": "Failed to list agents"
            },
            status_code=500
        )


@admin_required
async def create_agent(request: Request):
    """POST /api/admin/agents"""
    try:
        body = await request.json()
        name = body.get("agent_name", "").strip()
        
        if not name:
            return JSONResponse(
                {
                    "error": "invalid_input",
                    "message": "agent_name is required"
                },
                status_code=400
            )
        
        # Extract agent data (exclude agent_name)
        agent_data = {k: v for k, v in body.items() if k != "agent_name"}
        
        manager = get_config_manager()
        created = manager.create_agent(name, agent_data)
        
        return JSONResponse(
            {
                "agent_name": name,
                **created
            },
            status_code=201
        )
    
    except ValueError as e:
        logger.warning(f"Invalid agent creation: {e}")
        return JSONResponse(
            {
                "error": "invalid_input",
                "message": str(e)
            },
            status_code=400
        )
    except Exception as e:
        logger.error(f"Error creating agent: {e}", exc_info=True)
        return JSONResponse(
            {
                "error": "server_error",
                "message": "Failed to create agent"
            },
            status_code=500
        )


@admin_required
async def update_agent(request: Request):
    """PUT /api/admin/agents/{name}"""
    try:
        name = request.path_params.get("name", "").strip()
        body = await request.json()
        
        if not name:
            return JSONResponse(
                {
                    "error": "invalid_input",
                    "message": "Agent name is required"
                },
                status_code=400
            )
        
        manager = get_config_manager()
        updated = manager.update_agent(name, body)
        
        return JSONResponse({
            "agent_name": name,
            **updated
        })
    
    except ValueError as e:
        logger.warning(f"Invalid agent update: {e}")
        return JSONResponse(
            {
                "error": "not_found",
                "message": str(e)
            },
            status_code=404
        )
    except Exception as e:
        logger.error(f"Error updating agent: {e}", exc_info=True)
        return JSONResponse(
            {
                "error": "server_error",
                "message": "Failed to update agent"
            },
            status_code=500
        )


@admin_required
async def delete_agent(request: Request):
    """DELETE /api/admin/agents/{name}"""
    try:
        name = request.path_params.get("name", "").strip()
        
        if not name:
            return JSONResponse(
                {
                    "error": "invalid_input",
                    "message": "Agent name is required"
                },
                status_code=400
            )
        
        manager = get_config_manager()
        manager.delete_agent(name)
        
        return JSONResponse({"message": f"Agent '{name}' deleted"})
    
    except ValueError as e:
        logger.warning(f"Invalid agent deletion: {e}")
        return JSONResponse(
            {
                "error": "not_found",
                "message": str(e)
            },
            status_code=404
        )
    except Exception as e:
        logger.error(f"Error deleting agent: {e}", exc_info=True)
        return JSONResponse(
            {
                "error": "server_error",
                "message": "Failed to delete agent"
            },
            status_code=500
        )


# ============================================================================
# Backend Routes
# ============================================================================

@admin_required
async def list_backends(request: Request):
    """GET /api/admin/backends"""
    try:
        manager = get_config_manager()
        backends = manager.get_backends()
        
        # Convert to list format for API
        backends_list = []
        for name, config in backends.items():
            backend = {
                "backend_name": name,
                **config
            }
            backends_list.append(backend)
        
        logger.info(f"Listed {len(backends_list)} backends")
        return JSONResponse({"backends": backends_list})
    
    except Exception as e:
        logger.error(f"Error listing backends: {e}", exc_info=True)
        return JSONResponse(
            {
                "error": "server_error",
                "message": "Failed to list backends"
            },
            status_code=500
        )


@admin_required
async def create_backend(request: Request):
    """POST /api/admin/backends"""
    try:
        body = await request.json()
        name = body.get("backend_name", "").strip()
        
        if not name:
            return JSONResponse(
                {
                    "error": "invalid_input",
                    "message": "backend_name is required"
                },
                status_code=400
            )
        
        # Extract backend data (exclude backend_name)
        backend_data = {k: v for k, v in body.items() if k != "backend_name"}
        
        manager = get_config_manager()
        created = manager.create_backend(name, backend_data)
        
        return JSONResponse(
            {
                "backend_name": name,
                **created
            },
            status_code=201
        )
    
    except ValueError as e:
        logger.warning(f"Invalid backend creation: {e}")
        return JSONResponse(
            {
                "error": "invalid_input",
                "message": str(e)
            },
            status_code=400
        )
    except Exception as e:
        logger.error(f"Error creating backend: {e}", exc_info=True)
        return JSONResponse(
            {
                "error": "server_error",
                "message": "Failed to create backend"
            },
            status_code=500
        )


@admin_required
async def update_backend(request: Request):
    """PUT /api/admin/backends/{name}"""
    try:
        name = request.path_params.get("name", "").strip()
        body = await request.json()
        
        if not name:
            return JSONResponse(
                {
                    "error": "invalid_input",
                    "message": "Backend name is required"
                },
                status_code=400
            )
        
        manager = get_config_manager()
        updated = manager.update_backend(name, body)
        
        return JSONResponse({
            "backend_name": name,
            **updated
        })
    
    except ValueError as e:
        logger.warning(f"Invalid backend update: {e}")
        return JSONResponse(
            {
                "error": "not_found",
                "message": str(e)
            },
            status_code=404
        )
    except Exception as e:
        logger.error(f"Error updating backend: {e}", exc_info=True)
        return JSONResponse(
            {
                "error": "server_error",
                "message": "Failed to update backend"
            },
            status_code=500
        )


@admin_required
async def delete_backend(request: Request):
    """DELETE /api/admin/backends/{name}"""
    try:
        name = request.path_params.get("name", "").strip()
        
        if not name:
            return JSONResponse(
                {
                    "error": "invalid_input",
                    "message": "Backend name is required"
                },
                status_code=400
            )
        
        manager = get_config_manager()
        manager.delete_backend(name)
        
        return JSONResponse({"message": f"Backend '{name}' deleted"})
    
    except ValueError as e:
        logger.warning(f"Invalid backend deletion: {e}")
        return JSONResponse(
            {
                "error": "not_found",
                "message": str(e)
            },
            status_code=404
        )
    except Exception as e:
        logger.error(f"Error deleting backend: {e}", exc_info=True)
        return JSONResponse(
            {
                "error": "server_error",
                "message": "Failed to delete backend"
            },
            status_code=500
        )

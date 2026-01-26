"""
Agent authorization utilities for multi-agent support.

Provides functions to check agent permissions and generate authorization errors.
"""

import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


class AgentAuthorizationError(Exception):
    """Raised when agent is not authorized for a requested resource."""
    
    def __init__(self, agent_id: str, reason: str, details: Optional[Dict] = None):
        """
        Initialize authorization error.
        
        Args:
            agent_id: Agent identifier
            reason: Human-readable reason for denial
            details: Optional additional details
        """
        self.agent_id = agent_id
        self.reason = reason
        self.details = details or {}
        super().__init__(f"Agent {agent_id} not authorized: {reason}")


def check_agent_can_access_backend(
    agent_id: str,
    agent_config: Dict[str, Any],
    backend_name: str
) -> bool:
    """
    Check if agent is authorized to access a backend.
    
    Args:
        agent_id: Agent identifier
        agent_config: Agent configuration dictionary
        backend_name: Backend identifier
        
    Returns:
        True if authorized, False otherwise
        
    Raises:
        AgentAuthorizationError: If not authorized
    """
    if not agent_config:
        raise AgentAuthorizationError(agent_id, "Agent configuration not found")
    
    backend_access = agent_config.get("backend_access", [])
    
    if backend_name not in backend_access:
        raise AgentAuthorizationError(
            agent_id,
            f"Not authorized to access backend '{backend_name}'",
            {
                "backend_requested": backend_name,
                "backends_allowed": backend_access
            }
        )
    
    logger.debug(f"Agent {agent_id} authorized for backend {backend_name}")
    return True


def check_agent_has_scopes(
    agent_id: str,
    agent_config: Dict[str, Any],
    required_scopes: List[str]
) -> bool:
    """
    Check if agent has required scopes.
    
    Args:
        agent_id: Agent identifier
        agent_config: Agent configuration dictionary
        required_scopes: List of required scope names
        
    Returns:
        True if agent has all required scopes, False otherwise
        
    Raises:
        AgentAuthorizationError: If missing required scopes
    """
    if not agent_config:
        raise AgentAuthorizationError(agent_id, "Agent configuration not found")
    
    agent_scopes = agent_config.get("scopes", [])
    
    missing_scopes = [s for s in required_scopes if s not in agent_scopes]
    
    if missing_scopes:
        raise AgentAuthorizationError(
            agent_id,
            f"Missing required scopes: {missing_scopes}",
            {
                "required_scopes": required_scopes,
                "agent_scopes": agent_scopes,
                "missing_scopes": missing_scopes
            }
        )
    
    logger.debug(f"Agent {agent_id} has required scopes: {required_scopes}")
    return True


def create_authorization_error_response(
    error: AgentAuthorizationError
) -> Dict[str, Any]:
    """
    Create a JSON-RPC error response for authorization failure.
    
    Args:
        error: AgentAuthorizationError instance
        
    Returns:
        Error response dictionary
    """
    return {
        "error": "authorization_denied",
        "message": error.reason,
        "agent_id": error.agent_id,
        "details": error.details
    }


def create_missing_agent_error_response(reason: str = "Agent not found") -> Dict[str, Any]:
    """
    Create a JSON-RPC error response for missing agent.
    
    Args:
        reason: Optional custom error reason
        
    Returns:
        Error response dictionary
    """
    return {
        "error": "agent_not_found",
        "message": reason
    }


def create_invalid_agent_header_response() -> Dict[str, Any]:
    """
    Create a JSON-RPC error response for missing/invalid X-Agent-ID header.
    
    Returns:
        Error response dictionary
    """
    return {
        "error": "agent_header_missing",
        "message": "X-Agent-ID header is required for multi-agent gateway"
    }


class AgentAuthorizationChecker:
    """
    Convenience class for checking multiple authorization conditions.
    
    Usage:
        checker = AgentAuthorizationChecker(agent_id, agent_config)
        try:
            checker.check_backend_access(backend_name)
            checker.check_scopes(["mcp:read"])
        except AgentAuthorizationError as e:
            return create_authorization_error_response(e)
    """
    
    def __init__(self, agent_id: str, agent_config: Dict[str, Any]):
        """
        Initialize checker.
        
        Args:
            agent_id: Agent identifier
            agent_config: Agent configuration dictionary
        """
        self.agent_id = agent_id
        self.agent_config = agent_config
    
    def check_backend_access(self, backend_name: str) -> "AgentAuthorizationChecker":
        """
        Check backend access and raise if not authorized.
        
        Args:
            backend_name: Backend identifier
            
        Returns:
            Self for chaining
            
        Raises:
            AgentAuthorizationError
        """
        check_agent_can_access_backend(self.agent_id, self.agent_config, backend_name)
        return self
    
    def check_scopes(self, required_scopes: List[str]) -> "AgentAuthorizationChecker":
        """
        Check scopes and raise if not authorized.
        
        Args:
            required_scopes: List of required scope names
            
        Returns:
            Self for chaining
            
        Raises:
            AgentAuthorizationError
        """
        check_agent_has_scopes(self.agent_id, self.agent_config, required_scopes)
        return self


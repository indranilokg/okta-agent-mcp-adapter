"""
Agent extraction middleware for multi-agent support.

Extracts X-Agent-ID header from requests and validates agent configuration.
Used by ProxyHandler to support multi-agent routing.
"""

import logging
from typing import Optional, Tuple, Dict, Any

from okta_agent_proxy.storage import BackendConfigStore

logger = logging.getLogger(__name__)


class AgentExtractor:
    """
    Extracts and validates agent information from requests.
    
    Responsibilities:
    - Extract X-Agent-ID from request headers
    - Load agent configuration from store
    - Validate agent is enabled
    - Return agent config for downstream use
    """
    
    def __init__(self, store: BackendConfigStore):
        """
        Initialize agent extractor.
        
        Args:
            store: BackendConfigStore instance for agent lookup
        """
        self.store = store
    
    def extract_agent_from_headers(
        self,
        headers: Dict[str, str]
    ) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
        """
        Extract agent ID from request headers and load agent config.
        
        Args:
            headers: Request headers dictionary
            
        Returns:
            Tuple of (agent_id, agent_config) or (None, None) if not found/disabled
        """
        # Try to get X-Agent-ID header (case-insensitive)
        agent_id = None
        for key, value in headers.items():
            if key.lower() == "x-agent-id":
                agent_id = value
                break
        
        if not agent_id:
            logger.debug("No X-Agent-ID header in request")
            return None, None
        
        # Load agent config from store
        agent_config = self.store.get_agent(agent_id, enabled_only=True)
        
        if not agent_config:
            logger.warning(f"Agent '{agent_id}' not found or disabled")
            return agent_id, None
        
        logger.debug(f"Extracted agent: {agent_id}")
        return agent_id, agent_config
    
    def get_agent_backend_access(self, agent_id: str) -> list:
        """
        Get list of backends an agent can access.
        
        Args:
            agent_id: Agent identifier
            
        Returns:
            List of backend names the agent can access
        """
        return self.store.list_agent_backends(agent_id)


def extract_agent_id_from_headers(headers: Dict[str, str]) -> Optional[str]:
    """
    Simple utility to extract agent ID from headers.
    
    Args:
        headers: Request headers dictionary
        
    Returns:
        Agent ID if present, None otherwise
    """
    for key, value in headers.items():
        if key.lower() == "x-agent-id":
            return value
    return None


def validate_agent_access(
    agent_config: Dict[str, Any],
    backend_name: str
) -> bool:
    """
    Validate if an agent can access a specific backend.
    
    Args:
        agent_config: Agent configuration dictionary
        backend_name: Backend identifier
        
    Returns:
        True if agent can access backend, False otherwise
    """
    backend_access = agent_config.get("backend_access", [])
    can_access = backend_name in backend_access
    
    if not can_access:
        logger.warning(
            f"Agent '{agent_config.get('agent_id')}' cannot access backend '{backend_name}'. "
            f"Allowed backends: {backend_access}"
        )
    
    return can_access


def validate_agent_scopes(
    agent_config: Dict[str, Any],
    required_scopes: list
) -> bool:
    """
    Validate if agent has required scopes.
    
    Args:
        agent_config: Agent configuration dictionary
        required_scopes: List of required scopes
        
    Returns:
        True if agent has all required scopes, False otherwise
    """
    agent_scopes = agent_config.get("scopes", [])
    
    for scope in required_scopes:
        if scope not in agent_scopes:
            logger.warning(
                f"Agent '{agent_config.get('agent_id')}' missing scope '{scope}'. "
                f"Agent scopes: {agent_scopes}"
            )
            return False
    
    return True


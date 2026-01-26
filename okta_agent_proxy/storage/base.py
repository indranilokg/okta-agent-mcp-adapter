"""
Abstract backend configuration store interface.

Allows multiple implementations (in-memory, PostgreSQL, etc.)
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional


class BackendConfigStore(ABC):
    """
    Abstract base class for backend configuration storage.
    
    Implementations can use different backends (SQLite, PostgreSQL, etc.)
    but provide the same interface.
    """
    
    @abstractmethod
    def get_all_backends(self) -> List[Dict[str, Any]]:
        """
        Get all backend configurations.
        
        Returns:
            List of backend configs as dictionaries
        """
        pass
    
    @abstractmethod
    def get_backend(self, name: str) -> Optional[Dict[str, Any]]:
        """
        Get a specific backend by name.
        
        Args:
            name: Backend name
            
        Returns:
            Backend config as dictionary, or None if not found
        """
        pass
    
    @abstractmethod
    def create_backend(self, name: str, config: Dict[str, Any], user: str = "admin") -> bool:
        """
        Create a new backend.
        
        Args:
            name: Backend name (must be unique)
            config: Backend configuration
            user: User creating the backend
            
        Returns:
            True if created, False if already exists
            
        Raises:
            ValueError: If config is invalid
        """
        pass
    
    @abstractmethod
    def update_backend(self, name: str, config: Dict[str, Any], user: str = "admin") -> bool:
        """
        Update an existing backend.
        
        Args:
            name: Backend name
            config: Updated configuration
            user: User updating the backend
            
        Returns:
            True if updated, False if not found
            
        Raises:
            ValueError: If config is invalid
        """
        pass
    
    @abstractmethod
    def delete_backend(self, name: str, user: str = "admin") -> bool:
        """
        Delete a backend.
        
        Args:
            name: Backend name
            user: User deleting the backend
            
        Returns:
            True if deleted, False if not found
        """
        pass
    
    @abstractmethod
    def enable_backend(self, name: str, user: str = "admin") -> bool:
        """
        Enable a backend.
        
        Args:
            name: Backend name
            user: User enabling the backend
            
        Returns:
            True if enabled, False if not found
        """
        pass
    
    @abstractmethod
    def disable_backend(self, name: str, user: str = "admin") -> bool:
        """
        Disable a backend.
        
        Args:
            name: Backend name
            user: User disabling the backend
            
        Returns:
            True if disabled, False if not found
        """
        pass
    
    @abstractmethod
    def get_audit_log(self, backend_name: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get audit log entries.
        
        Args:
            backend_name: Filter by backend (optional)
            limit: Maximum number of entries to return
            
        Returns:
            List of audit log entries
        """
        pass

    # Agent-related methods
    
    @abstractmethod
    def get_agent(self, agent_id: str, enabled_only: bool = True) -> Optional[Dict[str, Any]]:
        """
        Get a specific agent by ID.
        
        Args:
            agent_id: Agent identifier
            enabled_only: If True, only return enabled agents
            
        Returns:
            Agent config as dictionary, or None if not found
        """
        pass
    
    @abstractmethod
    def get_agent_by_name(self, agent_name: str, enabled_only: bool = True) -> Optional[Dict[str, Any]]:
        """
        Get a specific agent by NAME (e.g., 'claude-code').
        
        Args:
            agent_name: Agent name from YAML config
            enabled_only: If True, only return enabled agents
            
        Returns:
            Agent config as dictionary, or None if not found
        """
        pass
    
    @abstractmethod
    def get_all_agents(self, enabled_only: bool = True) -> List[Dict[str, Any]]:
        """
        Get all agents.
        
        Args:
            enabled_only: If True, only return enabled agents
            
        Returns:
            List of agent configs as dictionaries
        """
        pass
    
    @abstractmethod
    def create_agent(self, agent_id: str, config: Dict[str, Any], user: str = "admin") -> bool:
        """
        Create a new agent.
        
        Args:
            agent_id: Agent identifier (must be unique)
            config: Agent configuration (client_id, private_key, scopes, backend_access)
            user: User creating the agent
            
        Returns:
            True if created, False if already exists
            
        Raises:
            ValueError: If config is invalid
        """
        pass
    
    @abstractmethod
    def update_agent(self, agent_id: str, config: Dict[str, Any], user: str = "admin") -> bool:
        """
        Update an existing agent.
        
        Args:
            agent_id: Agent identifier
            config: Updated configuration
            user: User updating the agent
            
        Returns:
            True if updated, False if not found
            
        Raises:
            ValueError: If config is invalid
        """
        pass
    
    @abstractmethod
    def delete_agent(self, agent_id: str, user: str = "admin") -> bool:
        """
        Delete an agent.
        
        Args:
            agent_id: Agent identifier
            user: User deleting the agent
            
        Returns:
            True if deleted, False if not found
        """
        pass
    
    @abstractmethod
    def enable_agent(self, agent_id: str, user: str = "admin") -> bool:
        """
        Enable an agent.
        
        Args:
            agent_id: Agent identifier
            user: User enabling the agent
            
        Returns:
            True if enabled, False if not found
        """
        pass
    
    @abstractmethod
    def disable_agent(self, agent_id: str, user: str = "admin") -> bool:
        """
        Disable an agent.
        
        Args:
            agent_id: Agent identifier
            user: User disabling the agent
            
        Returns:
            True if disabled, False if not found
        """
        pass
    
    @abstractmethod
    def get_agent_audit_log(self, agent_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get audit log entries for an agent.
        
        Args:
            agent_id: Agent identifier
            limit: Maximum number of entries to return
            
        Returns:
            List of audit log entries
        """
        pass
    
    @abstractmethod
    def list_agent_backends(self, agent_id: str) -> List[str]:
        """
        Get list of backends an agent can access.
        
        Args:
            agent_id: Agent identifier
            
        Returns:
            List of backend names
        """
        pass


"""
Config Manager

Handles reading and writing YAML configuration files.
"""

import logging
import yaml
import json
from typing import Dict, Any, List, Optional
from pathlib import Path
import copy

logger = logging.getLogger(__name__)


class ConfigManager:
    """Manages gateway configuration YAML file."""
    
    def __init__(self, config_path: str):
        """
        Initialize config manager.
        
        Args:
            config_path: Path to config.yaml
        """
        self.config_path = Path(config_path)
        self.config = None
        self._load_config()
    
    def _load_config(self):
        """Load configuration from YAML file."""
        try:
            with open(self.config_path, 'r') as f:
                self.config = yaml.safe_load(f)
            logger.info(f"Loaded config from {self.config_path}")
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            raise
    
    def _save_config(self):
        """Save configuration to YAML file."""
        try:
            # Create backup
            backup_path = self.config_path.with_suffix('.yaml.bak')
            if self.config_path.exists():
                with open(self.config_path, 'r') as f:
                    backup = f.read()
                with open(backup_path, 'w') as f:
                    f.write(backup)
                logger.info(f"Created backup at {backup_path}")
            
            # Write new config
            with open(self.config_path, 'w') as f:
                yaml.dump(self.config, f, default_flow_style=False, sort_keys=False)
            
            logger.info(f"Saved config to {self.config_path}")
        except Exception as e:
            logger.error(f"Failed to save config: {e}")
            raise
    
    def reload(self):
        """Reload configuration from disk."""
        self._load_config()
        logger.info("Configuration reloaded")
    
    # =========================================================================
    # Agent Management
    # =========================================================================
    
    def get_agents(self) -> Dict[str, Any]:
        """Get all agents."""
        return self.config.get("agents", {})
    
    def get_agent(self, name: str) -> Optional[Dict[str, Any]]:
        """Get specific agent."""
        agents = self.get_agents()
        return agents.get(name)
    
    def create_agent(self, name: str, agent_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create new agent."""
        agents = self.config.get("agents", {})
        
        if name in agents:
            raise ValueError(f"Agent '{name}' already exists")
        
        # Validate required fields
        required_fields = ["agent_id", "client_id", "private_key"]
        for field in required_fields:
            if field not in agent_data:
                raise ValueError(f"Missing required field: {field}")
        
        # Add agent
        agents[name] = agent_data
        self.config["agents"] = agents
        self._save_config()
        
        logger.info(f"Created agent: {name}")
        return agent_data
    
    def update_agent(self, name: str, agent_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update existing agent."""
        agents = self.config.get("agents", {})
        
        if name not in agents:
            raise ValueError(f"Agent '{name}' not found")
        
        # Merge updates
        agents[name].update(agent_data)
        self.config["agents"] = agents
        self._save_config()
        
        logger.info(f"Updated agent: {name}")
        return agents[name]
    
    def delete_agent(self, name: str):
        """Delete agent."""
        agents = self.config.get("agents", {})
        
        if name not in agents:
            raise ValueError(f"Agent '{name}' not found")
        
        del agents[name]
        self.config["agents"] = agents
        self._save_config()
        
        logger.info(f"Deleted agent: {name}")
    
    # =========================================================================
    # Backend Management
    # =========================================================================
    
    def get_backends(self) -> Dict[str, Any]:
        """Get all backends."""
        return self.config.get("backends", {})
    
    def get_backend(self, name: str) -> Optional[Dict[str, Any]]:
        """Get specific backend."""
        backends = self.get_backends()
        return backends.get(name)
    
    def create_backend(self, name: str, backend_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create new backend."""
        backends = self.config.get("backends", {})
        
        if name in backends:
            raise ValueError(f"Backend '{name}' already exists")
        
        # Validate required fields
        required_fields = ["url", "auth_method"]
        for field in required_fields:
            if field not in backend_data:
                raise ValueError(f"Missing required field: {field}")
        
        # Add backend
        backends[name] = backend_data
        self.config["backends"] = backends
        self._save_config()
        
        logger.info(f"Created backend: {name}")
        return backend_data
    
    def update_backend(self, name: str, backend_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update existing backend."""
        backends = self.config.get("backends", {})
        
        if name not in backends:
            raise ValueError(f"Backend '{name}' not found")
        
        # Merge updates
        backends[name].update(backend_data)
        self.config["backends"] = backends
        self._save_config()
        
        logger.info(f"Updated backend: {name}")
        return backends[name]
    
    def delete_backend(self, name: str):
        """Delete backend."""
        backends = self.config.get("backends", {})
        
        if name not in backends:
            raise ValueError(f"Backend '{name}' not found")
        
        del backends[name]
        self.config["backends"] = backends
        self._save_config()
        
        logger.info(f"Deleted backend: {name}")

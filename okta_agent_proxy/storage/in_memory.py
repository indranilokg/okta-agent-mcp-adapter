"""
In-memory SQLite backend configuration store.

Loads backends from YAML, stores in-memory SQLite, can sync back to YAML.
Perfect for prototyping with easy migration to PostgreSQL later.
"""

import logging
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional
import yaml

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import IntegrityError

from okta_agent_proxy.storage.base import BackendConfigStore
from okta_agent_proxy.storage.models import Base, BackendModel, BackendAuditLog, AgentModel

logger = logging.getLogger(__name__)


class InMemoryBackendStore(BackendConfigStore):
    """
    In-memory SQLite backend store that syncs with YAML.
    
    Features:
    - Loads initial config from YAML
    - Stores everything in SQLite in-memory database
    - Can write changes back to YAML
    - Thread-safe (SQLite handles locking)
    - Full CRUD operations
    - Audit logging of all changes
    """
    
    def __init__(self, yaml_file: str = "config/config.yaml"):
        """
        Initialize in-memory store and load from YAML.
        
        Args:
            yaml_file: Path to YAML configuration file
        """
        self.yaml_file = yaml_file
        
        # Create in-memory SQLite database
        logger.info("Initializing in-memory SQLite database")
        self.engine = create_engine("sqlite:///:memory:", echo=False)
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)
        
        # Load initial data from YAML
        self._load_from_yaml()
        self._load_agents_from_yaml()
        logger.info("In-memory store initialized")
    
    def _load_from_yaml(self):
        """Load backends from YAML file into in-memory database."""
        try:
            with open(self.yaml_file) as f:
                config = yaml.safe_load(f)
        except FileNotFoundError:
            logger.warning(f"YAML file not found: {self.yaml_file}")
            return
        except Exception as e:
            logger.error(f"Error loading YAML: {e}")
            return
        
        session = self.Session()
        try:
            backends_config = config.get("backends", {})
            logger.info(f"Loading {len(backends_config)} backends from YAML")
            
            for backend_name, backend_data in backends_config.items():
                try:
                    backend = BackendModel(
                        name=backend_name,
                        url=backend_data.get("url"),
                        paths=backend_data.get("paths", []),
                        auth_method=backend_data.get("auth_method", "okta-cross-app"),
                        auth_config=backend_data.get("auth_config", {}),
                        description=backend_data.get("description", ""),
                        timeout_seconds=backend_data.get("timeout_seconds", 30),
                        enabled=True,
                        created_by="system"
                    )
                    session.add(backend)
                    logger.debug(f"Loaded backend: {backend_name}")
                except Exception as e:
                    logger.error(f"Error loading backend {backend_name}: {e}")
                    continue
            
            session.commit()
            logger.info(f"Successfully loaded backends from {self.yaml_file}")
        except Exception as e:
            logger.error(f"Error during YAML load: {e}")
            session.rollback()
        finally:
            session.close()
    
    def _load_agents_from_yaml(self):
        """Load agents from YAML file into in-memory database."""
        try:
            with open(self.yaml_file) as f:
                config = yaml.safe_load(f)
        except FileNotFoundError:
            logger.warning(f"YAML file not found: {self.yaml_file}")
            return
        except Exception as e:
            logger.error(f"Error loading YAML: {e}")
            return
        
        session = self.Session()
        try:
            agents_config = config.get("agents", {})
            logger.info(f"Loading {len(agents_config)} agents from YAML")
            
            for agent_name, agent_data in agents_config.items():
                try:
                    agent = AgentModel(
                        agent_name=agent_name,  # Store the YAML key (e.g., "claude-code")
                        agent_id=agent_data.get("agent_id"),  # Get actual agent_id from config, not the YAML key
                        client_id=agent_data.get("client_id"),
                        private_key=agent_data.get("private_key"),
                        scopes=agent_data.get("scopes", ["mcp:read"]),
                        backend_access=agent_data.get("backend_access", []),
                        enabled=agent_data.get("enabled", True),
                        created_by="system"
                    )
                    session.add(agent)
                    logger.debug(f"Loaded agent: {agent_name}")
                except Exception as e:
                    logger.error(f"Error loading agent {agent_id}: {e}")
                    continue
            
            session.commit()
            logger.info(f"Successfully loaded agents from {self.yaml_file}")
        except Exception as e:
            logger.error(f"Error during agent load: {e}")
            session.rollback()
        finally:
            session.close()
    
    def get_all_backends(self) -> List[Dict[str, Any]]:
        """Get all backends from in-memory database."""
        session = self.Session()
        try:
            backends = session.query(BackendModel).filter_by(enabled=True).all()
            return [b.to_dict() for b in backends]
        except Exception as e:
            logger.error(f"Error getting all backends: {e}")
            return []
        finally:
            session.close()
    
    def get_backend(self, name: str) -> Optional[Dict[str, Any]]:
        """Get a specific backend by name."""
        session = self.Session()
        try:
            backend = session.query(BackendModel).filter_by(name=name).first()
            if backend:
                return backend.to_dict()
            return None
        except Exception as e:
            logger.error(f"Error getting backend {name}: {e}")
            return None
        finally:
            session.close()
    
    def create_backend(self, name: str, config: Dict[str, Any], user: str = "admin") -> bool:
        """Create a new backend in the in-memory database."""
        session = self.Session()
        try:
            # Check if already exists
            existing = session.query(BackendModel).filter_by(name=name).first()
            if existing:
                logger.warning(f"Backend {name} already exists")
                return False
            
            # Create new backend
            backend = BackendModel(
                name=name,
                url=config.get("url"),
                paths=config.get("paths", []),
                auth_method=config.get("auth_method", "okta-cross-app"),
                auth_config=config.get("auth_config", {}),
                description=config.get("description", ""),
                timeout_seconds=config.get("timeout_seconds", 30),
                enabled=True,
                created_by=user
            )
            session.add(backend)
            session.commit()
            
            # Log the action
            self._audit_log(session, name, "created", {}, config, user)
            
            logger.info(f"Backend {name} created by {user}")
            return True
        
        except IntegrityError:
            session.rollback()
            logger.warning(f"Backend {name} already exists (integrity error)")
            return False
        except Exception as e:
            session.rollback()
            logger.error(f"Error creating backend {name}: {e}")
            raise
        finally:
            session.close()
    
    def update_backend(self, name: str, config: Dict[str, Any], user: str = "admin") -> bool:
        """Update an existing backend."""
        session = self.Session()
        try:
            backend = session.query(BackendModel).filter_by(name=name).first()
            if not backend:
                logger.warning(f"Backend {name} not found for update")
                return False
            
            # Track what changed
            changes = {}
            
            if "url" in config and config["url"] != backend.url:
                changes["url"] = {"old": backend.url, "new": config["url"]}
                backend.url = config["url"]
            
            if "paths" in config and config["paths"] != backend.paths:
                changes["paths"] = {"old": backend.paths, "new": config["paths"]}
                backend.paths = config["paths"]
            
            if "auth_method" in config and config["auth_method"] != backend.auth_method:
                changes["auth_method"] = {"old": backend.auth_method, "new": config["auth_method"]}
                backend.auth_method = config["auth_method"]
            
            if "auth_config" in config and config["auth_config"] != backend.auth_config:
                changes["auth_config"] = {"old": backend.auth_config, "new": config["auth_config"]}
                backend.auth_config = config["auth_config"]
            
            if "description" in config and config["description"] != backend.description:
                changes["description"] = {"old": backend.description, "new": config["description"]}
                backend.description = config["description"]
            
            if "timeout_seconds" in config and config["timeout_seconds"] != backend.timeout_seconds:
                changes["timeout_seconds"] = {"old": backend.timeout_seconds, "new": config["timeout_seconds"]}
                backend.timeout_seconds = config["timeout_seconds"]
            
            backend.updated_by = user
            backend.updated_at = datetime.utcnow()
            session.commit()
            
            # Log the action
            self._audit_log(session, name, "updated", backend.to_dict(), changes, user)
            
            logger.info(f"Backend {name} updated by {user} ({len(changes)} changes)")
            return True
        
        except Exception as e:
            session.rollback()
            logger.error(f"Error updating backend {name}: {e}")
            raise
        finally:
            session.close()
    
    def delete_backend(self, name: str, user: str = "admin") -> bool:
        """Delete a backend (actually disables it)."""
        session = self.Session()
        try:
            backend = session.query(BackendModel).filter_by(name=name).first()
            if not backend:
                logger.warning(f"Backend {name} not found for deletion")
                return False
            
            # Store old state for audit
            old_config = backend.to_dict()
            
            # Actually delete
            session.delete(backend)
            session.commit()
            
            # Log the action
            self._audit_log(session, name, "deleted", old_config, {}, user)
            
            logger.info(f"Backend {name} deleted by {user}")
            return True
        
        except Exception as e:
            session.rollback()
            logger.error(f"Error deleting backend {name}: {e}")
            raise
        finally:
            session.close()
    
    def enable_backend(self, name: str, user: str = "admin") -> bool:
        """Enable a backend."""
        session = self.Session()
        try:
            backend = session.query(BackendModel).filter_by(name=name).first()
            if not backend:
                return False
            
            if backend.enabled:
                logger.debug(f"Backend {name} already enabled")
                return True
            
            backend.enabled = True
            backend.updated_by = user
            backend.updated_at = datetime.utcnow()
            session.commit()
            
            # Log the action
            self._audit_log(session, name, "enabled", {"enabled": False}, {"enabled": True}, user)
            
            logger.info(f"Backend {name} enabled by {user}")
            return True
        
        except Exception as e:
            session.rollback()
            logger.error(f"Error enabling backend {name}: {e}")
            raise
        finally:
            session.close()
    
    def disable_backend(self, name: str, user: str = "admin") -> bool:
        """Disable a backend."""
        session = self.Session()
        try:
            backend = session.query(BackendModel).filter_by(name=name).first()
            if not backend:
                return False
            
            if not backend.enabled:
                logger.debug(f"Backend {name} already disabled")
                return True
            
            backend.enabled = False
            backend.updated_by = user
            backend.updated_at = datetime.utcnow()
            session.commit()
            
            # Log the action
            self._audit_log(session, name, "disabled", {"enabled": True}, {"enabled": False}, user)
            
            logger.info(f"Backend {name} disabled by {user}")
            return True
        
        except Exception as e:
            session.rollback()
            logger.error(f"Error disabling backend {name}: {e}")
            raise
        finally:
            session.close()
    
    def get_audit_log(self, backend_name: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Get audit log entries."""
        session = self.Session()
        try:
            query = session.query(BackendAuditLog).order_by(BackendAuditLog.changed_at.desc())
            
            if backend_name:
                query = query.filter_by(backend_name=backend_name)
            
            logs = query.limit(limit).all()
            return [log.to_dict() for log in logs]
        except Exception as e:
            logger.error(f"Error getting audit log: {e}")
            return []
        finally:
            session.close()
    
    def sync_to_yaml(self):
        """Write in-memory database state back to YAML file."""
        session = self.Session()
        try:
            backends = session.query(BackendModel).all()
            agents = session.query(AgentModel).all()
            
            config = {
                "backends": {},
                "agents": {}
            }
            
            for backend in backends:
                config["backends"][backend.name] = {
                    "url": backend.url,
                    "paths": backend.paths,
                    "auth_method": backend.auth_method,
                    "auth_config": backend.auth_config,
                    "description": backend.description,
                    "timeout_seconds": backend.timeout_seconds
                }
            
            for agent in agents:
                config["agents"][agent.agent_id] = {
                    "client_id": agent.client_id,
                    "private_key": agent.private_key,
                    "scopes": agent.scopes,
                    "backend_access": agent.backend_access,
                    "enabled": agent.enabled
                }
            
            with open(self.yaml_file, "w") as f:
                yaml.dump(config, f, default_flow_style=False, sort_keys=False)
            
            logger.info(f"✓ Configuration synced to {self.yaml_file}")
        except Exception as e:
            logger.error(f"Error syncing to YAML: {e}")
            raise
        finally:
            session.close()
    
    def _audit_log(self, session, backend_name: str, action: str, old_state: Dict, new_state: Dict, user: str):
        """Create an audit log entry."""
        try:
            log = BackendAuditLog(
                id=str(uuid.uuid4()),
                backend_name=backend_name,
                action=action,
                changes={
                    "old": old_state,
                    "new": new_state
                },
                changed_by=user
            )
            session.add(log)
            session.commit()
        except Exception as e:
            logger.error(f"Error creating audit log: {e}")
            # Don't raise - audit logging shouldn't break the main operation
    
    # ======================== AGENT METHODS ========================
    
    def get_agent(self, agent_id: str, enabled_only: bool = True) -> Optional[Dict[str, Any]]:
        """Get a specific agent by ID."""
        session = self.Session()
        try:
            query = session.query(AgentModel).filter_by(agent_id=agent_id)
            if enabled_only:
                query = query.filter_by(enabled=True)
            agent = query.first()
            
            if agent:
                return {
                    "agent_name": agent.agent_name,
                    "agent_id": agent.agent_id,
                    "client_id": agent.client_id,
                    "private_key": agent.private_key,
                    "scopes": agent.scopes,
                    "backend_access": agent.backend_access,
                    "enabled": agent.enabled,
                    "created_by": agent.created_by,
                    "created_at": agent.created_at.isoformat(),
                    "updated_by": agent.updated_by,
                    "updated_at": agent.updated_at.isoformat()
                }
            return None
        except Exception as e:
            logger.error(f"Error getting agent {agent_id}: {e}")
            return None
        finally:
            session.close()
    
    def get_agent_by_name(self, agent_name: str, enabled_only: bool = True) -> Optional[Dict[str, Any]]:
        """Get a specific agent by NAME (e.g., 'claude-code')."""
        session = self.Session()
        try:
            query = session.query(AgentModel).filter_by(agent_name=agent_name)
            if enabled_only:
                query = query.filter_by(enabled=True)
            agent = query.first()
            
            if agent:
                return {
                    "agent_name": agent.agent_name,
                    "agent_id": agent.agent_id,
                    "client_id": agent.client_id,
                    "private_key": agent.private_key,
                    "scopes": agent.scopes,
                    "backend_access": agent.backend_access,
                    "enabled": agent.enabled,
                    "created_by": agent.created_by,
                    "created_at": agent.created_at.isoformat(),
                    "updated_by": agent.updated_by,
                    "updated_at": agent.updated_at.isoformat()
                }
            return None
        except Exception as e:
            logger.error(f"Error getting agent by name {agent_name}: {e}")
            return None
        finally:
            session.close()
    
    def get_all_agents(self, enabled_only: bool = True) -> List[Dict[str, Any]]:
        """Get all agents."""
        session = self.Session()
        try:
            query = session.query(AgentModel)
            if enabled_only:
                query = query.filter_by(enabled=True)
            agents = query.all()
            
            result = []
            for agent in agents:
                result.append({
                    "agent_id": agent.agent_id,
                    "client_id": agent.client_id,
                    "private_key": agent.private_key,
                    "scopes": agent.scopes,
                    "backend_access": agent.backend_access,
                    "enabled": agent.enabled,
                    "created_by": agent.created_by,
                    "created_at": agent.created_at.isoformat(),
                    "updated_by": agent.updated_by,
                    "updated_at": agent.updated_at.isoformat()
                })
            return result
        except Exception as e:
            logger.error(f"Error getting all agents: {e}")
            return []
        finally:
            session.close()
    
    def create_agent(self, agent_id: str, config: Dict[str, Any], user: str = "admin") -> bool:
        """Create a new agent."""
        session = self.Session()
        try:
            # Check if already exists
            existing = session.query(AgentModel).filter_by(agent_id=agent_id).first()
            if existing:
                logger.warning(f"Agent {agent_id} already exists")
                return False
            
            # Create new agent
            agent = AgentModel(
                agent_id=agent_id,
                client_id=config.get("client_id"),
                private_key=config.get("private_key"),
                scopes=config.get("scopes", ["mcp:read"]),
                backend_access=config.get("backend_access", []),
                enabled=config.get("enabled", True),
                created_by=user
            )
            session.add(agent)
            session.commit()
            
            logger.info(f"Agent {agent_id} created by {user}")
            return True
        
        except IntegrityError:
            session.rollback()
            logger.warning(f"Agent {agent_id} already exists (integrity error)")
            return False
        except Exception as e:
            session.rollback()
            logger.error(f"Error creating agent {agent_id}: {e}")
            raise
        finally:
            session.close()
    
    def update_agent(self, agent_id: str, config: Dict[str, Any], user: str = "admin") -> bool:
        """Update an existing agent."""
        session = self.Session()
        try:
            agent = session.query(AgentModel).filter_by(agent_id=agent_id).first()
            if not agent:
                logger.warning(f"Agent {agent_id} not found for update")
                return False
            
            # Update fields if provided
            if "client_id" in config:
                agent.client_id = config["client_id"]
            if "private_key" in config:
                agent.private_key = config["private_key"]
            if "scopes" in config:
                agent.scopes = config["scopes"]
            if "backend_access" in config:
                agent.backend_access = config["backend_access"]
            if "enabled" in config:
                agent.enabled = config["enabled"]
            
            agent.updated_by = user
            agent.updated_at = datetime.utcnow()
            session.commit()
            
            logger.info(f"Agent {agent_id} updated by {user}")
            return True
        
        except Exception as e:
            session.rollback()
            logger.error(f"Error updating agent {agent_id}: {e}")
            raise
        finally:
            session.close()
    
    def delete_agent(self, agent_id: str, user: str = "admin") -> bool:
        """Delete an agent."""
        session = self.Session()
        try:
            agent = session.query(AgentModel).filter_by(agent_id=agent_id).first()
            if not agent:
                logger.warning(f"Agent {agent_id} not found for deletion")
                return False
            
            session.delete(agent)
            session.commit()
            
            logger.info(f"Agent {agent_id} deleted by {user}")
            return True
        
        except Exception as e:
            session.rollback()
            logger.error(f"Error deleting agent {agent_id}: {e}")
            raise
        finally:
            session.close()
    
    def enable_agent(self, agent_id: str, user: str = "admin") -> bool:
        """Enable an agent."""
        session = self.Session()
        try:
            agent = session.query(AgentModel).filter_by(agent_id=agent_id).first()
            if not agent:
                return False
            
            if agent.enabled:
                logger.debug(f"Agent {agent_id} already enabled")
                return True
            
            agent.enabled = True
            agent.updated_by = user
            agent.updated_at = datetime.utcnow()
            session.commit()
            
            logger.info(f"Agent {agent_id} enabled by {user}")
            return True
        
        except Exception as e:
            session.rollback()
            logger.error(f"Error enabling agent {agent_id}: {e}")
            raise
        finally:
            session.close()
    
    def disable_agent(self, agent_id: str, user: str = "admin") -> bool:
        """Disable an agent."""
        session = self.Session()
        try:
            agent = session.query(AgentModel).filter_by(agent_id=agent_id).first()
            if not agent:
                return False
            
            if not agent.enabled:
                logger.debug(f"Agent {agent_id} already disabled")
                return True
            
            agent.enabled = False
            agent.updated_by = user
            agent.updated_at = datetime.utcnow()
            session.commit()
            
            logger.info(f"Agent {agent_id} disabled by {user}")
            return True
        
        except Exception as e:
            session.rollback()
            logger.error(f"Error disabling agent {agent_id}: {e}")
            raise
        finally:
            session.close()
    
    def get_agent_audit_log(self, agent_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Get audit log entries for an agent."""
        session = self.Session()
        try:
            # For now, we don't have a separate agent audit log table
            # Return an empty list
            logger.debug(f"Getting audit log for agent {agent_id}")
            return []
        except Exception as e:
            logger.error(f"Error getting agent audit log: {e}")
            return []
        finally:
            session.close()
    
    def list_agent_backends(self, agent_id: str) -> List[str]:
        """Get list of backends an agent can access."""
        agent = self.get_agent(agent_id, enabled_only=True)
        if agent:
            return agent.get("backend_access", [])
        return []


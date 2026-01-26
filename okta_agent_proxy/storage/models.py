"""
SQLAlchemy models for backend configuration storage.

Works with both in-memory SQLite and persistent PostgreSQL.
"""

from sqlalchemy import Column, String, Integer, Boolean, DateTime, JSON, Text
from sqlalchemy.orm import declarative_base
from datetime import datetime

Base = declarative_base()


class BackendModel(Base):
    """
    Backend MCP server configuration model.
    
    Stores:
    - Connection details (url, paths)
    - Authentication method and config
    - Metadata (description, timeout)
    - Audit trail (created_by, updated_by, timestamps)
    """
    
    __tablename__ = "backends"
    
    # Primary key
    name = Column(String(255), primary_key=True)
    
    # Connection details
    url = Column(String(2048), nullable=False)
    paths = Column(JSON, nullable=False)  # List of paths, e.g., ["/hr", "/employees"]
    
    # Authentication
    auth_method = Column(String(50), nullable=False)  # "okta-cross-app", "pre-shared-key", "service-account"
    auth_config = Column(JSON, nullable=True)  # Flexible config for each auth method
    
    # Metadata
    description = Column(Text, nullable=True)
    timeout_seconds = Column(Integer, default=30)
    enabled = Column(Boolean, default=True)
    
    # Audit trail
    created_by = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_by = Column(String(255), nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<BackendModel(name='{self.name}', url='{self.url}')>"
    
    def to_dict(self):
        """Convert model to dictionary for serialization."""
        return {
            "name": self.name,
            "url": self.url,
            "paths": self.paths,
            "auth_method": self.auth_method,
            "auth_config": self.auth_config,
            "description": self.description,
            "timeout_seconds": self.timeout_seconds,
            "enabled": self.enabled,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_by": self.updated_by,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
    
    @staticmethod
    def from_dict(data):
        """Create model from dictionary."""
        return BackendModel(
            name=data.get("name"),
            url=data.get("url"),
            paths=data.get("paths"),
            auth_method=data.get("auth_method"),
            auth_config=data.get("auth_config"),
            description=data.get("description"),
            timeout_seconds=data.get("timeout_seconds", 30),
            enabled=data.get("enabled", True),
            created_by=data.get("created_by", "system"),
        )


class BackendAuditLog(Base):
    """
    Audit log for backend configuration changes.
    
    Tracks all CRUD operations for compliance and debugging.
    """
    
    __tablename__ = "backend_audit_log"
    
    # Primary key
    id = Column(String(36), primary_key=True)  # UUID
    
    # Reference to backend
    backend_name = Column(String(255), nullable=False)
    
    # Action
    action = Column(String(50), nullable=False)  # "created", "updated", "deleted", "enabled", "disabled"
    
    # Change details
    changes = Column(JSON, nullable=True)  # What changed: {field: {old: x, new: y}}
    
    # Audit trail
    changed_by = Column(String(255), nullable=False)
    changed_at = Column(DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f"<BackendAuditLog(backend='{self.backend_name}', action='{self.action}')>"
    
    def to_dict(self):
        """Convert model to dictionary for serialization."""
        return {
            "id": self.id,
            "backend_name": self.backend_name,
            "action": self.action,
            "changes": self.changes,
            "changed_by": self.changed_by,
            "changed_at": self.changed_at.isoformat() if self.changed_at else None,
        }


class AgentModel(Base):
    """
    MCP Agent configuration model.
    
    Represents an MCP client (e.g., Cursor, Claude Code) that connects to the gateway.
    Each agent has own Okta credentials and backend access control.
    """
    
    __tablename__ = "agents"
    
    # Identity
    agent_name = Column(String(255), primary_key=True)  # e.g., "claude-code" (YAML key)
    agent_id = Column(String(255), nullable=False, unique=True)  # Service account ID (e.g., "wlpu1ohuuexps8K5X1d7")
    client_id = Column(String(255), nullable=False, unique=True)  # OAuth client ID
    private_key = Column(Text, nullable=False)  # PKCS8 format
    
    # Configuration
    scopes = Column(JSON, nullable=False)  # List of OAuth scopes
    backend_access = Column(JSON, nullable=False)  # List of backend names allowed
    
    # Status
    enabled = Column(Boolean, default=True)
    
    # Audit
    created_by = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_by = Column(String(255), nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<AgentModel(agent_id='{self.agent_id}', client_id='{self.client_id}')>"
    
    def to_dict(self):
        """Convert model to dictionary for serialization."""
        return {
            "agent_name": self.agent_name,
            "agent_id": self.agent_id,
            "client_id": self.client_id,
            "private_key": self.private_key,
            "scopes": self.scopes,
            "backend_access": self.backend_access,
            "enabled": self.enabled,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_by": self.updated_by,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


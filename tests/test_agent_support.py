"""
Tests for agent support and multi-agent configuration.

Tests agent CRUD operations, agent-backend access control, 
and agent configuration loading from YAML.
"""

import pytest
import os
import tempfile
import yaml
from datetime import datetime

from okta_agent_proxy.storage import InMemoryBackendStore
from okta_agent_proxy.config import AgentConfig


@pytest.fixture
def temp_yaml_file():
    """Create a temporary YAML config file with agents."""
    config = {
        "agents": {
            "cursor": {
                "client_id": "0oa_cursor",
                "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg...\n-----END PRIVATE KEY-----",
                "scopes": ["mcp:read", "mcp:write"],
                "backend_access": ["employees", "finance"],
                "enabled": True
            },
            "claude-code": {
                "client_id": "0oa_claude_code",
                "private_key": "-----BEGIN PRIVATE KEY-----\nDIIEvQIBADANBg...\n-----END PRIVATE KEY-----",
                "scopes": ["mcp:read"],
                "backend_access": ["partners"],
                "enabled": True
            }
        },
        "backends": {
            "employees": {
                "url": "http://localhost:9001",
                "paths": ["/employees"],
                "auth_method": "okta-cross-app",
                "description": "Employee MCP"
            }
        }
    }
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        yaml.dump(config, f)
        temp_path = f.name
    
    yield temp_path
    
    # Cleanup
    if os.path.exists(temp_path):
        os.unlink(temp_path)


class TestAgentLoading:
    """Test agent loading from YAML."""
    
    def test_load_agents_from_yaml(self, temp_yaml_file):
        """Test loading agents from YAML file."""
        store = InMemoryBackendStore(temp_yaml_file)
        
        agents = store.get_all_agents(enabled_only=False)
        assert len(agents) == 2
        
        agent_ids = {a["agent_id"] for a in agents}
        assert agent_ids == {"cursor", "claude-code"}
    
    def test_agent_config_fields(self, temp_yaml_file):
        """Test that agent config has all required fields."""
        store = InMemoryBackendStore(temp_yaml_file)
        
        agent = store.get_agent("cursor")
        assert agent is not None
        assert agent["client_id"] == "0oa_cursor"
        assert agent["scopes"] == ["mcp:read", "mcp:write"]
        assert agent["backend_access"] == ["employees", "finance"]
        assert agent["enabled"] is True
        
        # Check timestamps are present
        assert "created_at" in agent
        assert "updated_at" in agent


class TestAgentCRUD:
    """Test agent CRUD operations."""
    
    def test_get_agent(self, temp_yaml_file):
        """Test getting a specific agent."""
        store = InMemoryBackendStore(temp_yaml_file)
        
        agent = store.get_agent("cursor")
        assert agent is not None
        assert agent["agent_id"] == "cursor"
        assert agent["client_id"] == "0oa_cursor"
    
    def test_get_agent_not_found(self, temp_yaml_file):
        """Test getting a non-existent agent returns None."""
        store = InMemoryBackendStore(temp_yaml_file)
        
        agent = store.get_agent("nonexistent")
        assert agent is None
    
    def test_get_agent_disabled(self, temp_yaml_file):
        """Test disabled agents not returned by default."""
        store = InMemoryBackendStore(temp_yaml_file)
        
        # Disable agent
        store.disable_agent("cursor")
        
        # Should not be returned by default
        agent = store.get_agent("cursor")
        assert agent is None
        
        # But should be returned when enabled_only=False
        agent = store.get_agent("cursor", enabled_only=False)
        assert agent is not None
        assert agent["enabled"] is False
    
    def test_create_agent(self, temp_yaml_file):
        """Test creating a new agent."""
        store = InMemoryBackendStore(temp_yaml_file)
        
        config = {
            "client_id": "0oa_new_agent",
            "private_key": "-----BEGIN PRIVATE KEY-----\nNEWKEY...\n-----END PRIVATE KEY-----",
            "scopes": ["mcp:read"],
            "backend_access": ["employees"]
        }
        
        success = store.create_agent("new-agent", config, user="test_user")
        assert success is True
        
        agent = store.get_agent("new-agent")
        assert agent is not None
        assert agent["client_id"] == "0oa_new_agent"
        assert agent["created_by"] == "test_user"
    
    def test_create_duplicate_agent(self, temp_yaml_file):
        """Test creating duplicate agent returns False."""
        store = InMemoryBackendStore(temp_yaml_file)
        
        config = {
            "client_id": "0oa_duplicate",
            "private_key": "key",
            "backend_access": []
        }
        
        success = store.create_agent("cursor", config, user="test_user")
        assert success is False  # cursor already exists
    
    def test_update_agent(self, temp_yaml_file):
        """Test updating an agent."""
        store = InMemoryBackendStore(temp_yaml_file)
        
        updates = {
            "scopes": ["mcp:admin"],
            "backend_access": ["employees", "finance", "hr"]
        }
        
        success = store.update_agent("cursor", updates, user="test_user")
        assert success is True
        
        agent = store.get_agent("cursor")
        assert agent["scopes"] == ["mcp:admin"]
        assert agent["backend_access"] == ["employees", "finance", "hr"]
        assert agent["updated_by"] == "test_user"
    
    def test_update_nonexistent_agent(self, temp_yaml_file):
        """Test updating non-existent agent returns False."""
        store = InMemoryBackendStore(temp_yaml_file)
        
        success = store.update_agent("nonexistent", {}, user="test_user")
        assert success is False
    
    def test_delete_agent(self, temp_yaml_file):
        """Test deleting an agent."""
        store = InMemoryBackendStore(temp_yaml_file)
        
        assert store.get_agent("cursor") is not None
        
        success = store.delete_agent("cursor", user="test_user")
        assert success is True
        
        agent = store.get_agent("cursor", enabled_only=False)
        assert agent is None  # Agent actually deleted
    
    def test_delete_nonexistent_agent(self, temp_yaml_file):
        """Test deleting non-existent agent returns False."""
        store = InMemoryBackendStore(temp_yaml_file)
        
        success = store.delete_agent("nonexistent", user="test_user")
        assert success is False


class TestAgentEnableDisable:
    """Test agent enable/disable operations."""
    
    def test_enable_agent(self, temp_yaml_file):
        """Test enabling an agent."""
        store = InMemoryBackendStore(temp_yaml_file)
        
        # First disable
        store.disable_agent("cursor")
        agent = store.get_agent("cursor", enabled_only=False)
        assert agent["enabled"] is False
        
        # Now enable
        success = store.enable_agent("cursor", user="test_user")
        assert success is True
        
        agent = store.get_agent("cursor")
        assert agent is not None
        assert agent["enabled"] is True
    
    def test_disable_agent(self, temp_yaml_file):
        """Test disabling an agent."""
        store = InMemoryBackendStore(temp_yaml_file)
        
        success = store.disable_agent("cursor", user="test_user")
        assert success is True
        
        agent = store.get_agent("cursor")
        assert agent is None  # Disabled, so not returned
        
        agent = store.get_agent("cursor", enabled_only=False)
        assert agent["enabled"] is False
    
    def test_enable_already_enabled_agent(self, temp_yaml_file):
        """Test enabling already enabled agent succeeds."""
        store = InMemoryBackendStore(temp_yaml_file)
        
        agent = store.get_agent("cursor")
        assert agent["enabled"] is True
        
        # Try to enable again
        success = store.enable_agent("cursor", user="test_user")
        assert success is True  # Still succeeds
    
    def test_disable_already_disabled_agent(self, temp_yaml_file):
        """Test disabling already disabled agent succeeds."""
        store = InMemoryBackendStore(temp_yaml_file)
        
        store.disable_agent("cursor")
        
        # Try to disable again
        success = store.disable_agent("cursor", user="test_user")
        assert success is True  # Still succeeds


class TestAgentBackendAccess:
    """Test agent backend access control."""
    
    def test_list_agent_backends(self, temp_yaml_file):
        """Test listing backends accessible by an agent."""
        store = InMemoryBackendStore(temp_yaml_file)
        
        backends = store.list_agent_backends("cursor")
        assert backends == ["employees", "finance"]
        
        backends = store.list_agent_backends("claude-code")
        assert backends == ["partners"]
    
    def test_agent_with_no_backends(self, temp_yaml_file):
        """Test agent with empty backend access."""
        store = InMemoryBackendStore(temp_yaml_file)
        
        config = {
            "client_id": "0oa_no_access",
            "private_key": "key",
            "backend_access": []
        }
        
        store.create_agent("restricted", config)
        
        backends = store.list_agent_backends("restricted")
        assert backends == []
    
    def test_nonexistent_agent_backends(self, temp_yaml_file):
        """Test listing backends for non-existent agent."""
        store = InMemoryBackendStore(temp_yaml_file)
        
        backends = store.list_agent_backends("nonexistent")
        assert backends == []


class TestAgentAuditLog:
    """Test agent audit logging."""
    
    def test_get_agent_audit_log(self, temp_yaml_file):
        """Test getting agent audit log."""
        store = InMemoryBackendStore(temp_yaml_file)
        
        # Note: We currently return empty list as we don't have agent audit table yet
        log = store.get_agent_audit_log("cursor")
        assert isinstance(log, list)


class TestAgentYAMLSync:
    """Test syncing agents back to YAML."""
    
    def test_sync_agents_to_yaml(self, temp_yaml_file):
        """Test syncing updated agents back to YAML."""
        store = InMemoryBackendStore(temp_yaml_file)
        
        # Create a new agent
        config = {
            "client_id": "0oa_new",
            "private_key": "new_key",
            "scopes": ["mcp:read"],
            "backend_access": ["test"]
        }
        store.create_agent("new-agent", config)
        
        # Sync to YAML
        store.sync_to_yaml()
        
        # Load fresh store from same YAML
        store2 = InMemoryBackendStore(temp_yaml_file)
        
        agent = store2.get_agent("new-agent")
        assert agent is not None
        assert agent["client_id"] == "0oa_new"
        assert agent["backend_access"] == ["test"]
    
    def test_sync_agent_updates(self, temp_yaml_file):
        """Test syncing agent updates to YAML."""
        store = InMemoryBackendStore(temp_yaml_file)
        
        # Update agent
        store.update_agent("cursor", {"scopes": ["mcp:admin"]})
        
        # Sync to YAML
        store.sync_to_yaml()
        
        # Load fresh store
        store2 = InMemoryBackendStore(temp_yaml_file)
        
        agent = store2.get_agent("cursor")
        assert agent["scopes"] == ["mcp:admin"]


class TestAgentConfig:
    """Test AgentConfig model."""
    
    def test_agent_config_validation(self):
        """Test AgentConfig Pydantic model validation."""
        config = AgentConfig(
            agent_id="test",
            client_id="0oa_test",
            private_key="test_key",
            scopes=["mcp:read"],
            backend_access=["employees"]
        )
        
        assert config.agent_id == "test"
        assert config.client_id == "0oa_test"
        assert config.scopes == ["mcp:read"]
        assert config.backend_access == ["employees"]
    
    def test_agent_config_defaults(self):
        """Test AgentConfig default values."""
        config = AgentConfig(
            agent_id="test",
            client_id="0oa_test",
            private_key="test_key"
        )
        
        assert config.scopes == ["mcp:read"]
        assert config.backend_access == []


class TestGetAllAgents:
    """Test getting all agents."""
    
    def test_get_all_agents_enabled_only(self, temp_yaml_file):
        """Test getting only enabled agents."""
        store = InMemoryBackendStore(temp_yaml_file)
        
        # Disable one agent
        store.disable_agent("claude-code")
        
        agents = store.get_all_agents(enabled_only=True)
        assert len(agents) == 1
        assert agents[0]["agent_id"] == "cursor"
    
    def test_get_all_agents_including_disabled(self, temp_yaml_file):
        """Test getting all agents including disabled."""
        store = InMemoryBackendStore(temp_yaml_file)
        
        store.disable_agent("claude-code")
        
        agents = store.get_all_agents(enabled_only=False)
        assert len(agents) == 2
        
        agent_ids = {a["agent_id"] for a in agents}
        assert agent_ids == {"cursor", "claude-code"}
    
    def test_get_all_agents_empty(self, temp_yaml_file):
        """Test getting all agents when database is empty."""
        # Create fresh YAML without agents
        config = {"backends": {}}
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(config, f)
            temp_path = f.name
        
        try:
            store = InMemoryBackendStore(temp_path)
            
            agents = store.get_all_agents()
            assert agents == []
        finally:
            os.unlink(temp_path)


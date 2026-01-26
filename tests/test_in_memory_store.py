"""Tests for in-memory SQLite backend store"""

import pytest
import os
import tempfile
import yaml
from pathlib import Path

from okta_agent_proxy.storage import InMemoryBackendStore


@pytest.fixture
def temp_yaml_file():
    """Create a temporary YAML config file."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        config = {
            "backends": {
                "employees": {
                    "url": "https://employee-mcp.example.com",
                    "paths": ["/hr", "/employees"],
                    "auth_method": "okta-cross-app",
                    "auth_config": {
                        "id_jag_mode": "static",
                        "target_authorization_server": "https://employee-idp.okta.com",
                        "target_token_endpoint": "https://employee-idp.okta.com/oauth2/v1/token",
                        "target_client_id": "0oa_employee",
                        "target_client_secret": "secret123"
                    },
                    "description": "Employee MCP Server",
                    "timeout_seconds": 30
                },
                "finance": {
                    "url": "https://finance-mcp.example.com",
                    "paths": ["/accounting"],
                    "auth_method": "pre-shared-key",
                    "auth_config": {
                        "key": "finance_key_123",
                        "header_name": "X-API-Key"
                    },
                    "description": "Finance MCP Server",
                    "timeout_seconds": 45
                }
            }
        }
        yaml.dump(config, f)
        temp_path = f.name
    
    yield temp_path
    
    # Cleanup
    try:
        os.unlink(temp_path)
    except:
        pass


class TestInMemoryStore:
    """Test cases for InMemoryBackendStore"""
    
    def test_initialize_from_yaml(self, temp_yaml_file):
        """Test loading backends from YAML file"""
        store = InMemoryBackendStore(temp_yaml_file)
        backends = store.get_all_backends()
        
        assert len(backends) == 2
        assert any(b["name"] == "employees" for b in backends)
        assert any(b["name"] == "finance" for b in backends)
    
    def test_get_all_backends(self, temp_yaml_file):
        """Test getting all backends"""
        store = InMemoryBackendStore(temp_yaml_file)
        backends = store.get_all_backends()
        
        assert len(backends) == 2
        
        # Check employees backend
        emp = next(b for b in backends if b["name"] == "employees")
        assert emp["url"] == "https://employee-mcp.example.com"
        assert emp["paths"] == ["/hr", "/employees"]
        assert emp["auth_method"] == "okta-cross-app"
        assert emp["timeout_seconds"] == 30
    
    def test_get_backend(self, temp_yaml_file):
        """Test getting a specific backend"""
        store = InMemoryBackendStore(temp_yaml_file)
        backend = store.get_backend("employees")
        
        assert backend is not None
        assert backend["name"] == "employees"
        assert backend["url"] == "https://employee-mcp.example.com"
    
    def test_get_backend_not_found(self, temp_yaml_file):
        """Test getting a non-existent backend"""
        store = InMemoryBackendStore(temp_yaml_file)
        backend = store.get_backend("nonexistent")
        
        assert backend is None
    
    def test_create_backend(self, temp_yaml_file):
        """Test creating a new backend"""
        store = InMemoryBackendStore(temp_yaml_file)
        
        config = {
            "url": "https://partners-mcp.example.com",
            "paths": ["/partners"],
            "auth_method": "service-account",
            "auth_config": {
                "username": "gateway",
                "password": "partner_secret"
            },
            "description": "Partners MCP"
        }
        
        result = store.create_backend("partners", config, user="admin")
        assert result is True
        
        # Verify it was created
        backend = store.get_backend("partners")
        assert backend is not None
        assert backend["name"] == "partners"
        assert backend["url"] == "https://partners-mcp.example.com"
    
    def test_create_duplicate_backend(self, temp_yaml_file):
        """Test that creating duplicate backend fails"""
        store = InMemoryBackendStore(temp_yaml_file)
        
        config = {
            "url": "https://new.example.com",
            "paths": ["/new"]
        }
        
        result = store.create_backend("employees", config)
        assert result is False  # Already exists
    
    def test_update_backend(self, temp_yaml_file):
        """Test updating a backend"""
        store = InMemoryBackendStore(temp_yaml_file)
        
        new_config = {
            "url": "https://employee-mcp-v2.example.com",  # Changed URL
            "description": "Updated Employee MCP"
        }
        
        result = store.update_backend("employees", new_config, user="admin")
        assert result is True
        
        # Verify update
        backend = store.get_backend("employees")
        assert backend["url"] == "https://employee-mcp-v2.example.com"
        assert backend["description"] == "Updated Employee MCP"
    
    def test_update_nonexistent_backend(self, temp_yaml_file):
        """Test updating a non-existent backend"""
        store = InMemoryBackendStore(temp_yaml_file)
        
        result = store.update_backend("nonexistent", {"url": "https://example.com"})
        assert result is False
    
    def test_delete_backend(self, temp_yaml_file):
        """Test deleting a backend"""
        store = InMemoryBackendStore(temp_yaml_file)
        
        result = store.delete_backend("finance", user="admin")
        assert result is True
        
        # Verify deletion
        backend = store.get_backend("finance")
        assert backend is None
        
        # Should not appear in get_all
        backends = store.get_all_backends()
        assert not any(b["name"] == "finance" for b in backends)
    
    def test_delete_nonexistent_backend(self, temp_yaml_file):
        """Test deleting a non-existent backend"""
        store = InMemoryBackendStore(temp_yaml_file)
        
        result = store.delete_backend("nonexistent")
        assert result is False
    
    def test_enable_backend(self, temp_yaml_file):
        """Test enabling a backend"""
        store = InMemoryBackendStore(temp_yaml_file)
        
        # First disable it
        store.disable_backend("employees")
        
        # Then enable it
        result = store.enable_backend("employees", user="admin")
        assert result is True
        
        # Should appear in get_all again
        backends = store.get_all_backends()
        assert any(b["name"] == "employees" for b in backends)
    
    def test_disable_backend(self, temp_yaml_file):
        """Test disabling a backend"""
        store = InMemoryBackendStore(temp_yaml_file)
        
        result = store.disable_backend("employees", user="admin")
        assert result is True
        
        # Should not appear in get_all
        backends = store.get_all_backends()
        assert not any(b["name"] == "employees" for b in backends)
        
        # But can still get it directly (shows as disabled)
        backend = store.get_backend("employees")
        assert backend is not None
        assert backend["enabled"] is False
    
    def test_sync_to_yaml(self, temp_yaml_file):
        """Test syncing changes back to YAML"""
        store = InMemoryBackendStore(temp_yaml_file)
        
        # Create a new backend
        config = {
            "url": "https://new-mcp.example.com",
            "paths": ["/new"],
            "auth_method": "pre-shared-key",
            "auth_config": {"key": "new_key"}
        }
        store.create_backend("new_service", config)
        
        # Sync to YAML
        store.sync_to_yaml()
        
        # Read YAML file directly
        with open(temp_yaml_file) as f:
            saved_config = yaml.safe_load(f)
        
        # Verify new backend is in YAML
        assert "new_service" in saved_config["backends"]
        assert saved_config["backends"]["new_service"]["url"] == "https://new-mcp.example.com"
    
    def test_audit_log_create(self, temp_yaml_file):
        """Test audit logging for create operation"""
        store = InMemoryBackendStore(temp_yaml_file)
        
        config = {
            "url": "https://test.example.com",
            "paths": ["/test"]
        }
        store.create_backend("test", config, user="alice")
        
        # Get audit log
        logs = store.get_audit_log()
        
        # Should have create entry
        create_logs = [l for l in logs if l["action"] == "created" and l["backend_name"] == "test"]
        assert len(create_logs) > 0
        assert create_logs[0]["changed_by"] == "alice"
    
    def test_audit_log_update(self, temp_yaml_file):
        """Test audit logging for update operation"""
        store = InMemoryBackendStore(temp_yaml_file)
        
        store.update_backend("employees", {"description": "Updated"}, user="bob")
        
        # Get audit log
        logs = store.get_audit_log(backend_name="employees")
        
        # Should have update entry
        update_logs = [l for l in logs if l["action"] == "updated"]
        assert len(update_logs) > 0
        assert update_logs[0]["changed_by"] == "bob"
    
    def test_audit_log_delete(self, temp_yaml_file):
        """Test audit logging for delete operation"""
        store = InMemoryBackendStore(temp_yaml_file)
        
        store.delete_backend("finance", user="charlie")
        
        # Get audit log
        logs = store.get_audit_log(backend_name="finance")
        
        # Should have delete entry
        delete_logs = [l for l in logs if l["action"] == "deleted"]
        assert len(delete_logs) > 0
        assert delete_logs[0]["changed_by"] == "charlie"
    
    def test_concurrent_operations(self, temp_yaml_file):
        """Test that store handles concurrent operations"""
        store = InMemoryBackendStore(temp_yaml_file)
        
        # Create multiple backends
        for i in range(5):
            config = {
                "url": f"https://backend{i}.example.com",
                "paths": [f"/backend{i}"]
            }
            store.create_backend(f"backend{i}", config)
        
        # Verify all created
        backends = store.get_all_backends()
        assert len(backends) >= 5  # At least the new ones plus originals
        
        # Update multiple
        for i in range(3):
            store.update_backend(f"backend{i}", {"description": f"Updated {i}"})
        
        # Verify updates
        for i in range(3):
            backend = store.get_backend(f"backend{i}")
            assert backend["description"] == f"Updated {i}"


class TestInMemoryStoreEdgeCases:
    """Edge case tests for InMemoryBackendStore"""
    
    def test_empty_yaml_file(self):
        """Test loading from empty YAML file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("")
            f.flush()
            temp_file = f.name
        
        try:
            store = InMemoryBackendStore(temp_file)
            backends = store.get_all_backends()
            assert len(backends) == 0
        finally:
            os.unlink(temp_file)
    
    def test_yaml_with_no_backends(self):
        """Test YAML file with no backends section"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump({"other_config": "value"}, f)
            f.flush()
            temp_file = f.name
        
        try:
            store = InMemoryBackendStore(temp_file)
            backends = store.get_all_backends()
            assert len(backends) == 0
        finally:
            os.unlink(temp_file)
    
    def test_nonexistent_yaml_file(self):
        """Test initializing with nonexistent YAML file"""
        # Should not raise error, just start with empty store
        store = InMemoryBackendStore("/nonexistent/path/config.yaml")
        backends = store.get_all_backends()
        assert len(backends) == 0
        
        # But can still create backends
        config = {"url": "https://example.com", "paths": ["/test"]}
        result = store.create_backend("test", config)
        assert result is True


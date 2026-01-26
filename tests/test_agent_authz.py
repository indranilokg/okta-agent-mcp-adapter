"""
Tests for agent authorization and extraction.

Tests agent permission checking, authorization errors, and middleware.
"""

import pytest
import tempfile
import yaml
import os

from okta_agent_proxy.auth.agent_authz import (
    check_agent_can_access_backend,
    check_agent_has_scopes,
    create_authorization_error_response,
    create_missing_agent_error_response,
    create_invalid_agent_header_response,
    AgentAuthorizationError,
    AgentAuthorizationChecker
)
from okta_agent_proxy.middleware.agent_extractor import (
    AgentExtractor,
    extract_agent_id_from_headers,
    validate_agent_access,
    validate_agent_scopes
)
from okta_agent_proxy.storage import InMemoryBackendStore


@pytest.fixture
def agent_config():
    """Sample agent configuration."""
    return {
        "agent_id": "cursor",
        "client_id": "0oa_cursor",
        "private_key": "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----",
        "scopes": ["mcp:read", "mcp:write"],
        "backend_access": ["employees", "finance"]
    }


@pytest.fixture
def temp_yaml_with_agents():
    """Create a temporary YAML with agents for testing."""
    config = {
        "agents": {
            "cursor": {
                "client_id": "0oa_cursor",
                "private_key": "cursor_key",
                "scopes": ["mcp:read", "mcp:write"],
                "backend_access": ["employees", "finance"]
            },
            "claude-code": {
                "client_id": "0oa_claude",
                "private_key": "claude_key",
                "scopes": ["mcp:read"],
                "backend_access": ["partners"]
            }
        },
        "backends": {}
    }
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        yaml.dump(config, f)
        temp_path = f.name
    
    yield temp_path
    
    if os.path.exists(temp_path):
        os.unlink(temp_path)


class TestAgentBackendAccess:
    """Test agent backend access checks."""
    
    def test_agent_can_access_backend(self, agent_config):
        """Test agent can access allowed backend."""
        result = check_agent_can_access_backend(
            "cursor",
            agent_config,
            "employees"
        )
        assert result is True
    
    def test_agent_cannot_access_backend(self, agent_config):
        """Test agent cannot access denied backend."""
        with pytest.raises(AgentAuthorizationError) as exc_info:
            check_agent_can_access_backend(
                "cursor",
                agent_config,
                "hr"  # Not in backend_access
            )
        
        error = exc_info.value
        assert error.agent_id == "cursor"
        assert "Not authorized" in error.reason
        assert error.details["backend_requested"] == "hr"
    
    def test_agent_with_no_config(self):
        """Test error when agent config is None."""
        with pytest.raises(AgentAuthorizationError) as exc_info:
            check_agent_can_access_backend("unknown", None, "employees")
        
        assert exc_info.value.agent_id == "unknown"
    
    def test_agent_multiple_backends(self, agent_config):
        """Test agent with multiple allowed backends."""
        result = check_agent_can_access_backend("cursor", agent_config, "employees")
        assert result is True
        
        result = check_agent_can_access_backend("cursor", agent_config, "finance")
        assert result is True


class TestAgentScopes:
    """Test agent scope checks."""
    
    def test_agent_has_all_scopes(self, agent_config):
        """Test agent with all required scopes."""
        result = check_agent_has_scopes(
            "cursor",
            agent_config,
            ["mcp:read"]
        )
        assert result is True
    
    def test_agent_has_multiple_scopes(self, agent_config):
        """Test agent with multiple required scopes."""
        result = check_agent_has_scopes(
            "cursor",
            agent_config,
            ["mcp:read", "mcp:write"]
        )
        assert result is True
    
    def test_agent_missing_scope(self, agent_config):
        """Test agent missing required scope."""
        with pytest.raises(AgentAuthorizationError) as exc_info:
            check_agent_has_scopes(
                "cursor",
                agent_config,
                ["mcp:read", "mcp:admin"]  # admin not in scopes
            )
        
        error = exc_info.value
        assert "Missing required scopes" in error.reason
        assert "mcp:admin" in error.details["missing_scopes"]
    
    def test_agent_with_empty_scopes(self, agent_config):
        """Test agent with empty scopes list."""
        agent_config["scopes"] = []
        
        with pytest.raises(AgentAuthorizationError):
            check_agent_has_scopes("cursor", agent_config, ["mcp:read"])


class TestErrorResponses:
    """Test error response generation."""
    
    def test_authorization_error_response(self, agent_config):
        """Test authorization error response format."""
        try:
            check_agent_can_access_backend("cursor", agent_config, "denied")
        except AgentAuthorizationError as e:
            response = create_authorization_error_response(e)
        
        assert response["error"] == "authorization_denied"
        assert "agent_id" in response
        assert response["agent_id"] == "cursor"
        assert "details" in response
    
    def test_missing_agent_error_response(self):
        """Test missing agent error response."""
        response = create_missing_agent_error_response("Agent 'unknown' not found")
        
        assert response["error"] == "agent_not_found"
        assert "unknown" in response["message"]
    
    def test_invalid_agent_header_response(self):
        """Test invalid agent header response."""
        response = create_invalid_agent_header_response()
        
        assert response["error"] == "agent_header_missing"
        assert "X-Agent-ID" in response["message"]


class TestAgentExtractor:
    """Test agent extraction from headers."""
    
    def test_extract_agent_id_from_headers(self):
        """Test extracting agent ID from headers."""
        headers = {
            "Authorization": "Bearer token",
            "X-Agent-ID": "cursor"
        }
        
        agent_id = extract_agent_id_from_headers(headers)
        assert agent_id == "cursor"
    
    def test_extract_agent_id_case_insensitive(self):
        """Test agent ID extraction is case-insensitive."""
        headers = {
            "x-agent-id": "cursor",
            "Authorization": "Bearer token"
        }
        
        agent_id = extract_agent_id_from_headers(headers)
        assert agent_id == "cursor"
    
    def test_extract_agent_id_missing(self):
        """Test missing agent ID header."""
        headers = {
            "Authorization": "Bearer token"
        }
        
        agent_id = extract_agent_id_from_headers(headers)
        assert agent_id is None
    
    def test_agent_extractor_from_store(self, temp_yaml_with_agents):
        """Test AgentExtractor with real store."""
        store = InMemoryBackendStore(temp_yaml_with_agents)
        extractor = AgentExtractor(store)
        
        headers = {
            "X-Agent-ID": "cursor",
            "Authorization": "Bearer token"
        }
        
        agent_id, agent_config = extractor.extract_agent_from_headers(headers)
        
        assert agent_id == "cursor"
        assert agent_config is not None
        assert agent_config["client_id"] == "0oa_cursor"
    
    def test_agent_extractor_disabled_agent(self, temp_yaml_with_agents):
        """Test extractor with disabled agent."""
        store = InMemoryBackendStore(temp_yaml_with_agents)
        store.disable_agent("cursor")
        
        extractor = AgentExtractor(store)
        
        headers = {"X-Agent-ID": "cursor"}
        agent_id, agent_config = extractor.extract_agent_from_headers(headers)
        
        assert agent_id == "cursor"
        assert agent_config is None  # Disabled
    
    def test_agent_extractor_missing_agent(self, temp_yaml_with_agents):
        """Test extractor with non-existent agent."""
        store = InMemoryBackendStore(temp_yaml_with_agents)
        extractor = AgentExtractor(store)
        
        headers = {"X-Agent-ID": "nonexistent"}
        agent_id, agent_config = extractor.extract_agent_from_headers(headers)
        
        assert agent_id == "nonexistent"
        assert agent_config is None
    
    def test_get_agent_backend_access(self, temp_yaml_with_agents):
        """Test getting agent's backend access list."""
        store = InMemoryBackendStore(temp_yaml_with_agents)
        extractor = AgentExtractor(store)
        
        backends = extractor.get_agent_backend_access("cursor")
        assert backends == ["employees", "finance"]
        
        backends = extractor.get_agent_backend_access("claude-code")
        assert backends == ["partners"]


class TestValidationUtils:
    """Test validation utility functions."""
    
    def test_validate_agent_access_allowed(self, agent_config):
        """Test validating allowed backend access."""
        result = validate_agent_access(agent_config, "employees")
        assert result is True
    
    def test_validate_agent_access_denied(self, agent_config):
        """Test validating denied backend access."""
        result = validate_agent_access(agent_config, "denied")
        assert result is False
    
    def test_validate_agent_scopes_all_present(self, agent_config):
        """Test validating all required scopes present."""
        result = validate_agent_scopes(agent_config, ["mcp:read"])
        assert result is True
    
    def test_validate_agent_scopes_missing(self, agent_config):
        """Test validating missing required scopes."""
        result = validate_agent_scopes(agent_config, ["mcp:read", "mcp:admin"])
        assert result is False


class TestAuthorizationChecker:
    """Test AgentAuthorizationChecker for chaining."""
    
    def test_checker_backend_access(self, agent_config):
        """Test checker for backend access."""
        checker = AgentAuthorizationChecker("cursor", agent_config)
        
        # Should succeed
        result = checker.check_backend_access("employees")
        assert result is checker  # Returns self for chaining
    
    def test_checker_backend_access_denied(self, agent_config):
        """Test checker denies unauthorized backend."""
        checker = AgentAuthorizationChecker("cursor", agent_config)
        
        with pytest.raises(AgentAuthorizationError):
            checker.check_backend_access("denied")
    
    def test_checker_scopes(self, agent_config):
        """Test checker for scopes."""
        checker = AgentAuthorizationChecker("cursor", agent_config)
        
        result = checker.check_scopes(["mcp:read"])
        assert result is checker
    
    def test_checker_chaining(self, agent_config):
        """Test checker chaining multiple checks."""
        checker = AgentAuthorizationChecker("cursor", agent_config)
        
        # Should succeed and return self for chaining
        result = (checker
                  .check_backend_access("employees")
                  .check_scopes(["mcp:read"]))
        
        assert result is checker
    
    def test_checker_chaining_fails(self, agent_config):
        """Test checker chaining stops on first error."""
        checker = AgentAuthorizationChecker("cursor", agent_config)
        
        with pytest.raises(AgentAuthorizationError):
            (checker
             .check_backend_access("employees")
             .check_backend_access("denied"))  # Should fail here


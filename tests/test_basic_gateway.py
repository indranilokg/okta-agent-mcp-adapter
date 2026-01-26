"""
Basic gateway tests for Phase 1
Tests routing, caching, and configuration
"""

import pytest
from okta_agent_proxy.backends import BackendRouter
from okta_agent_proxy.cache import TokenCache
from okta_agent_proxy.config import BackendConfig, GatewayConfig


class TestTokenCache:
    """Tests for TokenCache"""
    
    def test_cache_initialization(self, token_cache):
        """Test cache initialization"""
        assert token_cache.max_size == 100
        assert token_cache.ttl_seconds == 3600
        assert len(token_cache.cache) == 0
    
    def test_cache_set_and_get(self, token_cache):
        """Test setting and getting a token"""
        user_id = "user123"
        backend = "employees"
        token = "test_token_xyz"
        
        token_cache.set(user_id, backend, token)
        retrieved = token_cache.get(user_id, backend)
        
        assert retrieved == token
    
    def test_cache_miss(self, token_cache):
        """Test cache miss returns None"""
        result = token_cache.get("nonexistent", "backend")
        assert result is None
    
    def test_cache_invalidate_single(self, token_cache):
        """Test invalidating a single token"""
        user_id = "user123"
        backend = "employees"
        
        token_cache.set(user_id, backend, "token1")
        token_cache.set(user_id, "partners", "token2")
        
        token_cache.invalidate(user_id, backend)
        
        assert token_cache.get(user_id, backend) is None
        assert token_cache.get(user_id, "partners") is not None
    
    def test_cache_invalidate_all_user(self, token_cache):
        """Test invalidating all tokens for a user"""
        user_id = "user123"
        
        token_cache.set(user_id, "employees", "token1")
        token_cache.set(user_id, "partners", "token2")
        
        token_cache.invalidate(user_id)
        
        assert token_cache.get(user_id, "employees") is None
        assert token_cache.get(user_id, "partners") is None
    
    def test_cache_stats(self, token_cache):
        """Test cache statistics"""
        token_cache.set("user1", "backend1", "token1")
        token_cache.set("user2", "backend2", "token2")
        
        stats = token_cache.stats()
        
        assert stats["current_size"] == 2
        assert stats["max_size"] == 100
        assert stats["usage_percent"] == 2.0
        assert stats["ttl_seconds"] == 3600
    
    def test_cache_clear(self, token_cache):
        """Test clearing the cache"""
        token_cache.set("user1", "backend1", "token1")
        token_cache.set("user2", "backend2", "token2")
        
        token_cache.clear()
        
        assert token_cache.get("user1", "backend1") is None
        assert token_cache.get("user2", "backend2") is None


class TestBackendRouter:
    """Tests for BackendRouter"""
    
    def test_router_initialization(self, backend_router):
        """Test router initialization with backends"""
        backends_list = backend_router.list_backends()
        assert "test_backend" in backends_list
        assert backends_list["test_backend"]["url"] == "http://localhost:8001"
    
    def test_get_backend_for_path(self, backend_router):
        """Test getting backend for a path"""
        backend = backend_router.get_backend_for_path("/test")
        assert backend == "test_backend"
    
    def test_get_backend_for_path_not_found(self, backend_router):
        """Test backend not found for path"""
        backend = backend_router.get_backend_for_path("/nonexistent")
        assert backend is None
    
    def test_get_backend_config(self, backend_router, backend_config):
        """Test getting backend configuration"""
        config = backend_router.get_backend_config("test_backend")
        assert config == backend_config
        assert config.url == "http://localhost:8001"
    
    def test_get_backend_url(self, backend_router):
        """Test getting backend URL"""
        url = backend_router.get_backend_url("test_backend")
        assert url == "http://localhost:8001"
    
    def test_list_routes(self, backend_router):
        """Test listing all routes"""
        routes = backend_router.list_routes()
        assert routes["/test"] == "test_backend"
    
    def test_path_with_mcp_suffix(self, mock_env_vars):
        """Test path matching with /mcp suffix"""
        from unittest.mock import patch
        backend_config = BackendConfig(
            name="test",
            url="http://localhost:8001",
            paths=["/hr"],
            description="Test"
        )
        with patch("okta_agent_proxy.backends.router.get_id_jag_issuer"):
            with patch("okta_agent_proxy.backends.router.get_id_jag_exchanger"):
                router = BackendRouter({"test": backend_config})
        
        # Should match /hr and /hr/mcp
        assert router.get_backend_for_path("/hr") == "test"
        assert router.get_backend_for_path("/hr/mcp") == "test"


class TestGatewayConfig:
    """Tests for gateway configuration"""
    
    def test_gateway_config_creation(self, gateway_config):
        """Test creating gateway configuration"""
        assert gateway_config.name == "Okta MCP Gateway"
        assert "test_backend" in gateway_config.backends
    
    def test_gateway_settings_from_env(self, gateway_settings):
        """Test loading settings from environment"""
        assert gateway_settings.okta_domain == "dev-12345.okta.com"
        assert gateway_settings.okta_client_id == "test_client_id"
        assert gateway_settings.gateway_port == 8000
    
    def test_backend_config_creation(self, backend_config):
        """Test creating backend configuration"""
        assert backend_config.name == "test_backend"
        assert backend_config.url == "http://localhost:8001"
        assert "/test" in backend_config.paths


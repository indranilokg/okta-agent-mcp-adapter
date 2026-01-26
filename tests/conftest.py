"""
Pytest configuration and fixtures
"""

import pytest
import os
from unittest.mock import MagicMock, patch

from okta_agent_proxy.config import GatewaySettings, GatewayConfig, BackendConfig, CacheConfig
from okta_agent_proxy.backends import BackendRouter
from okta_agent_proxy.cache import TokenCache


@pytest.fixture
def mock_env_vars(monkeypatch):
    """Mock environment variables"""
    monkeypatch.setenv("OKTA_DOMAIN", "dev-12345.okta.com")
    monkeypatch.setenv("OKTA_CLIENT_ID", "test_client_id")
    monkeypatch.setenv("OKTA_CLIENT_SECRET", "test_client_secret")
    monkeypatch.setenv("OKTA_ISSUER", "https://dev-12345.okta.com")
    monkeypatch.setenv("GATEWAY_BASE_URL", "http://localhost:8000")
    monkeypatch.setenv("GATEWAY_PORT", "8000")
    monkeypatch.setenv("LOG_LEVEL", "INFO")


@pytest.fixture
def gateway_settings(mock_env_vars):
    """Create test gateway settings"""
    return GatewaySettings()


@pytest.fixture
def backend_config():
    """Create test backend configuration"""
    return BackendConfig(
        name="test_backend",
        url="http://localhost:8001",
        paths=["/test"],
        description="Test backend",
        timeout_seconds=30
    )


@pytest.fixture
def backend_router(backend_config, mock_env_vars):
    """Create test backend router"""
    backends = {"test_backend": backend_config}
    with patch("okta_agent_proxy.backends.router.get_id_jag_issuer"):
        with patch("okta_agent_proxy.backends.router.get_id_jag_exchanger"):
            return BackendRouter(backends)


@pytest.fixture
def token_cache():
    """Create test token cache"""
    return TokenCache(max_size=100, ttl_seconds=3600)


@pytest.fixture
def gateway_config(gateway_settings, backend_config):
    """Create test gateway configuration"""
    return GatewayConfig(
        gateway=gateway_settings,
        cache=CacheConfig(max_size=100, ttl_seconds=3600),
        backends={"test_backend": backend_config}
    )


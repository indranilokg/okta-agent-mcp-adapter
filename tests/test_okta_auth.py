"""
Phase 2: Okta Authentication Tests

Tests for:
- OktaTokenValidator with JWT validation
- Protected Resource Metadata endpoint
- WWW-Authenticate header generation
- Bearer token extraction
"""

import pytest
import json
import os
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime, timedelta

from jose import JWTError
from jose import jwt as jose_jwt
from okta_agent_proxy.auth.okta_validator import OktaTokenValidator, validate_bearer_token
from okta_agent_proxy.metadata import get_protected_resource_metadata
from okta_agent_proxy.middleware.auth import (
    extract_bearer_token,
    extract_scopes_from_claims,
    create_401_response,
    AuthContext
)


class TestOktaTokenValidator:
    """Test Okta JWT token validation"""
    
    @pytest.fixture
    def validator(self):
        """Create validator instance"""
        return OktaTokenValidator(
            okta_domain="dev-12345.okta.com",
            okta_client_id="0oa1234567890abcdef",
            gateway_base_url="http://localhost:8000",
            jwks_cache_ttl=3600
        )
    
    def test_validator_initialization(self, validator):
        """Test validator initializes correctly"""
        assert validator.okta_domain == "dev-12345.okta.com"
        assert validator.okta_client_id == "0oa1234567890abcdef"
        assert validator.issuer == "https://dev-12345.okta.com"
        assert validator.gateway_base_url == "http://localhost:8000"
    
    def test_validator_requires_config(self):
        """Test validator raises error without required config"""
        with pytest.raises(ValueError):
            OktaTokenValidator(
                okta_domain=None,
                okta_client_id="test",
                gateway_base_url="http://localhost"
            )
    
    def test_jwks_cache_creation(self, validator):
        """Test JWKS cache is created"""
        assert validator.jwks_cache is not None
        assert validator.jwks_cache.maxsize == 10
        assert validator.jwks_cache.ttl == 3600
    
    @pytest.mark.asyncio
    async def test_fetch_jwks_caching(self, validator):
        """Test JWKS is cached after first fetch"""
        mock_jwks = {
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "test-key-id",
                    "use": "sig",
                    "n": "test-n",
                    "e": "AQAB"
                }
            ]
        }
        
        # Manually populate the cache to test caching behavior
        validator.jwks_cache["jwks"] = mock_jwks
        
        # Should return cached value without making HTTP call
        result = await validator.fetch_jwks()
        assert result == mock_jwks
        
        # Clear cache for next test
        validator.clear_cache()
    
    @pytest.mark.asyncio
    async def test_validate_token_success(self, validator):
        """Test token validation succeeds with valid token"""
        # Create a test token (without signature validation for now)
        claims = {
            "sub": "user123",
            "iss": "https://dev-12345.okta.com",
            "aud": ["0oa1234567890abcdef", "http://localhost:8000"],
            "exp": datetime.now().timestamp() + 3600,
            "iat": datetime.now().timestamp(),
            "scp": "mcp:read mcp:write"
        }
        
        mock_jwks = {
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "test-key-id",
                    "use": "sig",
                    "n": "test-n",
                    "e": "AQAB"
                }
            ]
        }
        
        # Pre-cache the JWKS
        validator.jwks_cache["jwks"] = mock_jwks
        
        with patch("okta_agent_proxy.auth.okta_validator.jwt.get_unverified_claims") as mock_unverified:
            with patch("okta_agent_proxy.auth.okta_validator.jwt.decode") as mock_decode:
                mock_unverified.return_value = claims
                mock_decode.return_value = claims
                
                result = await validator.validate_token("test-token")
                assert result == claims
                assert result["sub"] == "user123"
        
        validator.clear_cache()
    
    @pytest.mark.asyncio
    async def test_validate_token_fails_invalid_signature(self, validator):
        """Test token validation fails with invalid signature"""
        mock_jwks = {
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "test-key-id",
                    "use": "sig",
                    "n": "test-n",
                    "e": "AQAB"
                }
            ]
        }
        
        with patch("httpx.AsyncClient.get") as mock_get:
            mock_response = AsyncMock()
            mock_response.json.return_value = mock_jwks
            mock_response.raise_for_status = AsyncMock()
            mock_get.return_value = mock_response
            
            with patch("okta_agent_proxy.auth.okta_validator.jwt.decode") as mock_decode:
                mock_decode.side_effect = JWTError("Invalid signature")
                
                result = await validator.validate_token("invalid-token")
                assert result is None
    
    @pytest.mark.asyncio
    async def test_validate_token_with_scopes(self, validator):
        """Test token validation with required scopes"""
        claims = {
            "sub": "user123",
            "iss": "https://dev-12345.okta.com",
            "aud": "0oa1234567890abcdef",
            "exp": datetime.now().timestamp() + 3600,
            "scp": "mcp:read mcp:write admin"
        }
        
        mock_jwks = {"keys": []}
        
        # Pre-cache the JWKS
        validator.jwks_cache["jwks"] = mock_jwks
        
        with patch("okta_agent_proxy.auth.okta_validator.jwt.get_unverified_claims") as mock_unverified:
            with patch("okta_agent_proxy.auth.okta_validator.jwt.decode") as mock_decode:
                mock_unverified.return_value = claims
                mock_decode.return_value = claims
                
                # Should succeed with matching scopes
                result = await validator.validate_token(
                    "test-token",
                    required_scopes=["mcp:read"]
                )
                assert result is not None
                
                # Should fail with missing scopes
                result = await validator.validate_token(
                    "test-token",
                    required_scopes=["missing:scope"]
                )
                assert result is None
        
        validator.clear_cache()
    
    def test_clear_cache(self, validator):
        """Test JWKS cache can be cleared"""
        validator.jwks_cache["jwks"] = {"test": "data"}
        assert "jwks" in validator.jwks_cache
        
        validator.clear_cache()
        assert "jwks" not in validator.jwks_cache


class TestBearerTokenExtraction:
    """Test Bearer token extraction from Authorization header"""
    
    def test_extract_valid_bearer_token(self):
        """Test extracting valid Bearer token"""
        header = "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
        token = extract_bearer_token(header)
        assert token == "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
    
    def test_extract_no_header(self):
        """Test extraction with no Authorization header"""
        result = extract_bearer_token(None)
        assert result is None
    
    def test_extract_invalid_format(self):
        """Test extraction with invalid format"""
        # Too many parts
        result = extract_bearer_token("Bearer token extra")
        assert result is None
        
        # Wrong scheme
        result = extract_bearer_token("Basic token")
        assert result is None
        
        # Only one part
        result = extract_bearer_token("Bearer")
        assert result is None
    
    def test_extract_case_insensitive_scheme(self):
        """Test Bearer scheme is case-insensitive"""
        header = "bearer token123"
        token = extract_bearer_token(header)
        assert token == "token123"
        
        header = "BEARER token456"
        token = extract_bearer_token(header)
        assert token == "token456"


class TestScopeExtraction:
    """Test scope extraction from JWT claims"""
    
    def test_extract_scopes_as_string(self):
        """Test extracting scopes from space-separated string"""
        claims = {"scp": "mcp:read mcp:write admin"}
        scopes = extract_scopes_from_claims(claims)
        assert scopes == ["mcp:read", "mcp:write", "admin"]
    
    def test_extract_scopes_as_list(self):
        """Test extracting scopes from list"""
        claims = {"scp": ["mcp:read", "mcp:write"]}
        scopes = extract_scopes_from_claims(claims)
        assert scopes == ["mcp:read", "mcp:write"]
    
    def test_extract_scopes_missing(self):
        """Test extracting scopes when missing"""
        claims = {"sub": "user123"}
        scopes = extract_scopes_from_claims(claims)
        assert scopes == []
    
    def test_extract_scopes_invalid_type(self):
        """Test extracting scopes with invalid type"""
        claims = {"scp": 123}  # Invalid type
        scopes = extract_scopes_from_claims(claims)
        assert scopes == []


class TestAuthContext:
    """Test AuthContext for request authentication"""
    
    def test_auth_context_creation(self):
        """Test creating AuthContext"""
        claims = {
            "sub": "user123",
            "scp": "mcp:read mcp:write"
        }
        ctx = AuthContext(
            token="test-token",
            claims=claims,
            scopes=["mcp:read", "mcp:write"],
            is_valid=True
        )
        
        assert ctx.token == "test-token"
        assert ctx.user_id == "user123"
        assert ctx.is_valid is True
    
    def test_auth_context_scope_checking(self):
        """Test scope checking methods"""
        ctx = AuthContext(
            token="test-token",
            scopes=["mcp:read", "mcp:write"]
        )
        
        assert ctx.has_scope("mcp:read") is True
        assert ctx.has_scope("admin") is False
        
        assert ctx.has_any_scope(["mcp:read", "admin"]) is True
        assert ctx.has_any_scope(["admin", "other"]) is False
        
        assert ctx.has_all_scopes(["mcp:read", "mcp:write"]) is True
        assert ctx.has_all_scopes(["mcp:read", "admin"]) is False


class TestWWWAuthenticateHeader:
    """Test WWW-Authenticate header generation"""
    
    def test_create_401_response(self):
        """Test creating 401 response with WWW-Authenticate header"""
        status, headers, body = create_401_response(
            gateway_base_url="http://localhost:8000",
            scope="mcp:read mcp:write"
        )
        
        assert status == 401
        assert "WWW-Authenticate" in headers
        assert headers["Content-Type"] == "application/json"
        
        # Check header format
        www_auth = headers["WWW-Authenticate"]
        assert "Bearer" in www_auth
        assert "resource_metadata=" in www_auth
        assert "localhost:8000/.well-known/oauth-protected-resource" in www_auth
        assert "scope=" in www_auth
        
        # Check body
        body_dict = json.loads(body)
        assert body_dict["error"] == "unauthorized"
        assert "error_description" in body_dict


class TestProtectedResourceMetadata:
    """Test Protected Resource Metadata endpoint"""
    
    def test_protected_resource_metadata(self):
        """Test Protected Resource Metadata generation"""
        with patch.dict(os.environ, {
            "OKTA_DOMAIN": "dev-12345.okta.com",
            "OKTA_ISSUER": "https://dev-12345.okta.com",
            "GATEWAY_BASE_URL": "http://localhost:8000"
        }):
            metadata = get_protected_resource_metadata()
            
            assert "resource_documentation_uri" in metadata
            assert "authorization_servers" in metadata
            assert "resource_identification" in metadata
            assert "scopes_supported" in metadata
            
            assert metadata["authorization_servers"][0] == "https://dev-12345.okta.com"
            assert "mcp:read" in metadata["scopes_supported"]
            assert "mcp:write" in metadata["scopes_supported"]


class TestValidateBearerToken:
    """Test the validate_bearer_token convenience function"""
    
    @pytest.mark.asyncio
    async def test_validate_bearer_token_valid_format(self):
        """Test validating Bearer token with valid format"""
        with patch("okta_agent_proxy.auth.okta_validator.get_validator") as mock_get:
            mock_validator = AsyncMock()
            mock_validator.validate_token.return_value = {
                "sub": "user123",
                "aud": "client123"
            }
            mock_get.return_value = mock_validator
            
            result = await validate_bearer_token("Bearer test-token")
            assert result["sub"] == "user123"
    
    @pytest.mark.asyncio
    async def test_validate_bearer_token_no_header(self):
        """Test validating with no Authorization header"""
        result = await validate_bearer_token(None)
        assert result is None
    
    @pytest.mark.asyncio
    async def test_validate_bearer_token_invalid_format(self):
        """Test validating with invalid header format"""
        result = await validate_bearer_token("Invalid header format")
        assert result is None


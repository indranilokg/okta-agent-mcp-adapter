"""
Configuration management for MCP Gateway
"""

import os
from typing import Dict, List, Optional
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings
import yaml
from dotenv import load_dotenv

# Load .env file at module import time
load_dotenv()


class AgentConfig(BaseModel):
    """Agent (MCP client) configuration
    
    Two purposes:
    
    1. Frontend User Authentication:
       - client_id: OAuth client ID for user login flow
       - client_secret: OAuth client secret for user login flow
       - Returns: ID Token + Access Token for the user
    
    2. Cross-App Access (ID-JAG Exchange):
       - agent_id: Service account identifier (used as principal_id in JWT)
       - private_key: JWK format private key for signing JWT assertions
       - User's ID Token is exchanged for ID-JAG at org auth server
       - ID-JAG is then exchanged at target auth server for MCP access token
    
    Note: Scopes for token exchange come from backend.auth_config, not agent config.
          The ID-JAG token will contain scopes from the ID token + backend-requested scopes.
    """
    agent_id: str
    client_id: str  # OAuth client ID (for user authentication)
    client_secret: str  # OAuth client secret (for user authentication)
    private_key: str  # JWK private key (for JWT signing in ID-JAG exchange)
    backend_access: List[str] = Field(default_factory=list)  # Backends this agent can access


class BackendAuthConfig(BaseModel):
    """Backend authentication configuration
    
    Supports THREE authentication methods:
    
    1. okta-cross-app (IETF ID-JAG Pattern)
       Per: https://www.ietf.org/archive/id/draft-ietf-oauth-identity-assertion-authz-grant-00.html
       
       Flow:
       - User authenticates with agent OAuth → gets ID token (org-level scopes)
       - ID token exchanged for ID-JAG at org auth server
       - ID-JAG exchanged at target auth server for MCP access token
       - Target auth server's authorization policies determine MCP token scopes
       
       NOTE: The proxy does NOT configure scopes. Scopes are determined by Okta's
             authorization policies at the target auth server during the exchange.
       
       TWO PATTERNS:
       
       A) Static Pattern (configured):
          Target auth server details pre-configured at gateway
          Faster, no discovery needed
          
          Config:
            id_jag_mode: static
            target_authorization_server: https://target-idp.okta.com/oauth2/ausscimnps4vnh9zE1d7
            target_audience: mcp_resource_server
       
       B) Dynamic Pattern (discovered):
          Gateway discovers auth server details from target's protected resource metadata
          More flexible, works with compliant targets
          
          Config:
            id_jag_mode: dynamic
    
    2. pre-shared-key (Static API Key)
       Static key configured at gateway
       Same key used for all requests
       Scopes not applicable
       
       Config:
         key: api_key_123
         header_name: X-API-Key  (optional, default: "X-API-Key")
    
    3. service-account (Basic Auth)
       Gateway authenticates as service account
       Uses Basic Auth (username:password)
       Scopes not applicable
       
       Config:
         username: service_account_id
         password: service_account_secret
    """
    # For okta-cross-app method
    id_jag_mode: Optional[str] = Field(default="static")  # "static" or "dynamic"
    target_authorization_server: Optional[str] = None
    target_token_endpoint: Optional[str] = None
    target_client_id: Optional[str] = None
    target_client_secret: Optional[str] = None
    target_audience: Optional[str] = None
    
    # For pre-shared-key method
    key: Optional[str] = None
    header_name: Optional[str] = Field(default="X-API-Key")
    
    # For service-account method
    username: Optional[str] = None
    password: Optional[str] = None


class BackendConfig(BaseModel):
    """Single backend MCP server configuration"""
    name: str
    url: str
    paths: List[str]
    description: str
    timeout_seconds: int = 30
    auth_method: str = "okta-cross-app"  # "okta-cross-app", "pre-shared-key", or "service-account"
    auth_config: BackendAuthConfig = Field(default_factory=BackendAuthConfig)


class CacheConfig(BaseModel):
    """Token cache configuration"""
    max_size: int = 50000
    ttl_seconds: int = 3600


class GatewaySettings(BaseSettings):
    """
    Gateway settings from environment variables.
    
    In a multi-agent architecture:
    - OKTA_DOMAIN: Required (for JWKS validation)
    - OKTA_CLIENT_ID, OKTA_CLIENT_SECRET: Optional (agent credentials are in config.yaml)
    - OKTA_ISSUER: Optional (derived from OKTA_DOMAIN if not set)
    """
    okta_domain: str = Field(alias="OKTA_DOMAIN")
    okta_client_id: Optional[str] = Field(alias="OKTA_CLIENT_ID", default=None)
    okta_client_secret: Optional[str] = Field(alias="OKTA_CLIENT_SECRET", default=None)
    okta_issuer: Optional[str] = Field(alias="OKTA_ISSUER", default=None)
    okta_authorization_server_id: str = Field(alias="OKTA_AUTHORIZATION_SERVER_ID", default="default")
    
    gateway_base_url: str = Field(alias="GATEWAY_BASE_URL", default="http://localhost:8000")
    gateway_port: int = Field(alias="GATEWAY_PORT", default=8000)
    
    log_level: str = Field(alias="LOG_LEVEL", default="INFO")
    
    class Config:
        env_file = ".env"
        case_sensitive = False
    
    @property
    def issuer(self) -> str:
        """Get issuer URL (use provided value or derive from OKTA_DOMAIN)"""
        if self.okta_issuer:
            return self.okta_issuer
        return f"https://{self.okta_domain}"


class GatewayConfig(BaseModel):
    """Complete gateway configuration"""
    name: str = "Okta MCP Gateway"
    version: str = "1.0.0"
    description: str = "Okta-secured MCP proxy gateway"
    
    gateway: GatewaySettings
    cache: CacheConfig = Field(default_factory=CacheConfig)
    backends: Dict[str, BackendConfig] = Field(default_factory=dict)
    agents: Dict[str, AgentConfig] = Field(default_factory=dict)
    
    @classmethod
    def from_yaml(cls, config_path: str, env_settings: Optional[GatewaySettings] = None) -> "GatewayConfig":
        """Load configuration from YAML file and environment"""
        with open(config_path, "r") as f:
            yaml_config = yaml.safe_load(f)
        
        # Use provided settings or load from environment
        if env_settings is None:
            env_settings = GatewaySettings()
        
        # Build backends config
        backends_raw = yaml_config.get("backends", {})
        backends = {}
        for backend_name, backend_data in backends_raw.items():
            backends[backend_name] = BackendConfig(
                name=backend_name,
                **backend_data
            )
        
        # Build agents config
        agents_raw = yaml_config.get("agents", {})
        agents = {}
        for agent_id, agent_data in agents_raw.items():
            # agent_data already has agent_id from YAML, so just pass it directly
            agents[agent_id] = AgentConfig(**agent_data)
        
        # Build cache config
        cache_raw = yaml_config.get("cache", {})
        cache_config = CacheConfig(**cache_raw.get("backend_tokens", {}))
        
        return cls(
            gateway=env_settings,
            cache=cache_config,
            backends=backends,
            agents=agents
        )


def load_config() -> GatewayConfig:
    """Load configuration from environment and YAML"""
    config_path = os.getenv("CONFIG_PATH", "config/config.yaml")
    
    env_settings = GatewaySettings()
    
    if os.path.exists(config_path):
        return GatewayConfig.from_yaml(config_path, env_settings)
    else:
        # Minimal config from env only
        return GatewayConfig(
            gateway=env_settings,
            cache=CacheConfig(),
            backends={},
            agents={}
        )


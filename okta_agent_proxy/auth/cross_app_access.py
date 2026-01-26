"""
Okta Cross-App Access (ID-JAG) Manager

Enables secure token exchange for MCP access using Okta AI SDK.
Implements the 4-step ID-JAG flow:
1. Exchange ID token for ID-JAG token
2. Verify ID-JAG token (optional, for audit)
3. Exchange ID-JAG for authorization server token
4. Verify authorization server token

This module provides clean abstractions for the ID-JAG pattern without
needing custom JWT handling.
"""

import logging
import os
import json
from typing import Dict, Any, Optional
from datetime import datetime

try:
    from jose import jwt
except ImportError:
    jwt = None

try:
    from okta_ai_sdk import OktaAISDK, OktaAIConfig, AuthServerTokenRequest
except ImportError as e:
    raise ImportError(
        f"okta-ai-sdk-proto>=1.0.0a6 is required. "
        f"Install with: pip install --upgrade --extra-index-url https://test.pypi.org/simple/ okta-ai-sdk-proto\n"
        f"Error details: {e}"
    )

logger = logging.getLogger(__name__)


class OktaCrossAppAccessManager:
    """
    Manages ID-JAG token exchange for MCP server access using Okta AI SDK.
    
    This implementation follows the pattern from okta-agentic-ai-demo:
    - Uses OktaAISDK for clean, high-level token exchange
    - Supports both static and dynamic auth server discovery
    - Handles agent-specific credentials
    - Provides token verification for audit trails
    
    Usage:
        manager = OktaCrossAppAccessManager()
        mcp_token = await manager.exchange_id_to_mcp_token(user_id_token, backend_name)
        is_valid = await manager.verify_mcp_token(mcp_token, backend_name)
    """
    
    def __init__(self, agent_id: str = None, client_id: str = None, agent_private_key = None, okta_domain: str = None, target_auth_server_id: str = None):
        """
        Initialize the Cross-App Access Manager with SDK configuration.
        
        Args:
            agent_id: Service account ID for JWT signing (from agent config, principalId)
            client_id: OAuth app client ID (from agent config, for JWT assertion issuer)
            agent_private_key: Private key in JWK format (from agent config)
            okta_domain: Okta domain - can be just domain or full URL (will be normalized)
            target_auth_server_id: Target authorization server ID (from backend config)
        """
        # Get Okta domain
        raw_domain = okta_domain or os.getenv("OKTA_DOMAIN", "").strip()
        if not raw_domain:
            raise ValueError("OKTA_DOMAIN environment variable or parameter is required")
        
        # Normalize domain - OktaAISDK expects HTTPS URL
        if raw_domain.startswith("http://"):
            self.okta_domain = raw_domain.replace("http://", "https://")
        elif raw_domain.startswith("https://"):
            self.okta_domain = raw_domain
        else:
            # Assume it's just domain name, add https://
            self.okta_domain = f"https://{raw_domain}"
        
        # Get agent credentials (preferring parameters, then environment variables)
        # IMPORTANT: agent_id is NOT the same as client_id - do NOT fall back to client_id
        logger.debug(f"[ID-JAG] Constructor parameters: agent_id={agent_id}, client_id={client_id}, target_auth_server_id={target_auth_server_id}")
        self.agent_id = agent_id or os.getenv("OKTA_CHAT_ASSISTANT_AGENT_ID")
        self.client_id = client_id or os.getenv("OKTA_CLIENT_ID")
        self.target_auth_server_id = target_auth_server_id
        logger.debug(f"[ID-JAG] After fallback: agent_id={self.agent_id}, client_id={self.client_id}, target_auth_server_id={self.target_auth_server_id}")
        
        if agent_private_key is not None:
            agent_private_key_str = agent_private_key
        else:
            agent_private_key_str = os.getenv("OKTA_CHAT_ASSISTANT_AGENT_PRIVATE_KEY")
        
        if not self.agent_id or not self.client_id or not agent_private_key_str:
            logger.warning(f"Agent credentials not fully configured. ID-JAG exchange will be disabled. agent_id={self.agent_id}, client_id={self.client_id}, has_key={bool(agent_private_key_str)}")
            self.sdk_main = None
            self.sdk_mcp_configs = {}
            return
        
        try:
            # Parse private key if it's a JSON string
            if isinstance(agent_private_key_str, str) and agent_private_key_str.startswith("{"):
                self.agent_private_key = json.loads(agent_private_key_str)
            else:
                self.agent_private_key = agent_private_key_str
            
            logger.debug(f"[ID-JAG] Agent private key type: {type(self.agent_private_key)}, has kty: {'kty' in self.agent_private_key if isinstance(self.agent_private_key, dict) else 'N/A'}")
            
            # STEP 1 Config: ID token → ID-JAG token exchange at TARGET auth server
            # For JWT bearer authentication, we need:
            # - clientId: OAuth app client ID (for the JWT iss/sub)
            # - principalId: Agent ID (service account for JWT assertion)
            # - privateJWK: Agent's private key for signing
            # - authorizationServerId: TARGET auth server (where we're exchanging TO)
            
            # Extract auth server ID if it's a full URL (e.g., "https://domain/oauth2/auss2fth0mcIXHzVO1d7" -> "auss2fth0mcIXHzVO1d7")
            auth_server_id = self.target_auth_server_id
            if auth_server_id and auth_server_id.startswith("https://"):
                # Extract the ID part after /oauth2/
                auth_server_id = auth_server_id.split("/oauth2/")[-1]
                logger.debug(f"[ID-JAG] Extracted auth server ID from URL: {self.target_auth_server_id} -> {auth_server_id}")
            
            main_config = OktaAIConfig(
                oktaDomain=self.okta_domain,  # Full HTTPS URL
                clientId=self.client_id.strip(),  # OAuth app client ID (from agent config)
                clientSecret="",  # Not used with JWT bearer
                authorizationServerId=auth_server_id or "default",  # Target auth server for token exchange
                principalId=self.agent_id.strip(),  # Agent/service account ID (subject of JWT assertion)
                privateJWK=self.agent_private_key  # Key for signing JWT
            )
            
            logger.info(f"OktaAIConfig created for {self.client_id}")
            logger.debug(f"  oktaDomain: {self.okta_domain}, principalId: {self.agent_id}, authorizationServerId: {self.target_auth_server_id}")
            
            self.sdk_main = OktaAISDK(config=main_config)
            logger.info(f"Main SDK initialized for ID-JAG exchange (okta_domain={self.okta_domain}, client_id={self.client_id}, agent_id={self.agent_id}, target_auth_server={self.target_auth_server_id})")
            
            # Cache for MCP SDK instances per backend
            self.sdk_mcp_configs = {}
            
        except Exception as e:
            logger.error(f"Failed to initialize OktaCrossAppAccessManager: {e}", exc_info=True)
            raise
    
    def _get_or_create_mcp_sdk(self, backend_name: str, auth_server_id: str) -> Optional[OktaAISDK]:
        """
        Get or create SDK instance for MCP token exchange.
        
        Args:
            backend_name: Name of the backend (e.g., "employees", "finance")
            auth_server_id: Authorization server ID at the target
        
        Returns:
            OktaAISDK instance or None if not configured
        """
        if not self.sdk_main:
            return None
        
        cache_key = f"{backend_name}:{auth_server_id}"
        
        if cache_key not in self.sdk_mcp_configs:
            try:
                # STEP 3 Config: ID-JAG → MCP auth server token exchange
                # NOTE: clientId here is the service account/agent identifier, not an OAuth client ID
                mcp_config = OktaAIConfig(
                    oktaDomain=self.okta_domain,
                    clientId=self.agent_id.strip(),  # Agent ID (service account identifier for JWT)
                    clientSecret="",  # Not used with JWT bearer
                    authorizationServerId=auth_server_id,  # MCP authorization server
                    principalId=self.agent_id.strip(),  # Agent ID (subject of JWT assertion)
                    privateJWK=self.agent_private_key  # Key for signing JWT
                )
                
                sdk = OktaAISDK(config=mcp_config)
                self.sdk_mcp_configs[cache_key] = sdk
                logger.info(f"MCP SDK created for {backend_name} (auth_server: {auth_server_id})")
            except Exception as e:
                logger.error(f"Failed to create MCP SDK for {backend_name}: {e}")
                return None
        
        return self.sdk_mcp_configs[cache_key]
    
    async def exchange_id_token_to_mcp_token(
        self,
        user_id_token: str,
        backend_name: str,
        target_auth_server_id: str,
        scopes: Optional[list] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Exchange user's ID token for MCP access token using ID-JAG (3-step flow).
        
        Implements RFC8693 Token Exchange with ID-JAG pattern:
        1. Exchange ID token for ID-JAG token at target auth server
        2. Verify ID-JAG token (optional, for audit trail)
        3. Exchange ID-JAG for authorization server token (at target MCP server)
        
        Args:
            user_id_token: User's ID token from Okta (obtained from user login via agent OAuth)
            backend_name: Name of the backend MCP server
            target_auth_server_id: Authorization server ID at the target MCP server
            scopes: Optional scopes to request (default: ["mcp:read"])
            
        Returns:
            Dict with access_token, expires_in, token_type, scope, or None if failed
        """
        if not self.sdk_main:
            logger.error("ID-JAG SDK not configured")
            return None
        
        try:
            if not scopes:
                scopes = ["mcp:read"]
            
            scope_str = " ".join(scopes) if isinstance(scopes, list) else scopes
            logger.debug(f"[ID-JAG] Starting token exchange for {backend_name} with scopes: {scope_str}")
        
            # STEP 1: Exchange ID token for ID-JAG token at target auth server
            # Per okta-ai-sdk-proto docs, use token_type="id_token" for ID tokens
            id_jag_audience = f"{self.okta_domain}/oauth2/{target_auth_server_id}"
            logger.debug(f"[ID-JAG] STEP 1: Exchanging ID token at target auth server: {id_jag_audience}")
            
            try:
                # We're exchanging an access token which has the cid (client id) claim
                # Use token_type="access_token" for RFC8693 token exchange
                logger.debug(f"[ID-JAG] STEP 1 Parameters: token_type=access_token, audience={id_jag_audience}, scope={scope_str}, token_length={len(user_id_token)}")
                
                # Decode token to log its payload
                try:
                    if jwt:
                        token_payload = jwt.get_unverified_claims(user_id_token)
                        logger.info(f"[ID-JAG] Source Token Payload (unverified): {token_payload}")
                        logger.info(f"[ID-JAG] Source Token - aud={token_payload.get('aud')}, cid={token_payload.get('cid')}, sub={token_payload.get('sub')}, token_use={token_payload.get('token_use')}, scope={token_payload.get('scope')}")
                    else:
                        logger.warning("[ID-JAG] jwt library not available for token decoding")
                except Exception as e:
                    logger.warning(f"[ID-JAG] Could not decode token payload: {e}")
                
                # Log token details (first and last chars for security)
                token_preview = f"{user_id_token[:20]}...{user_id_token[-20:]}" if len(user_id_token) > 40 else user_id_token[:40]
                logger.debug(f"[ID-JAG] Token preview: {token_preview}")
                
                # Log SDK configuration
                logger.info(f"[ID-JAG] SDK Config: oktaDomain={self.okta_domain}, clientId={self.client_id}, principalId={self.agent_id}, authorizationServerId={target_auth_server_id or 'default'}")
                logger.debug(f"[ID-JAG] Private key has kty={self.agent_private_key.get('kty') if isinstance(self.agent_private_key, dict) else 'unknown'}")
                
                # Log exact SDK method call parameters
                logger.info(f"[ID-JAG STEP 1] Exchanging ID token for ID-JAG token at {id_jag_audience}")
                id_jag_result = self.sdk_main.cross_app_access.exchange_token(
                    token=user_id_token,
                    audience=id_jag_audience,
                    scope=scope_str,
                    token_type="id_token"  # ID token from Okta OAuth (required for RFC8693)
                )
                logger.info(f"[ID-JAG] STEP 1 SUCCESS: ID-JAG token expires_in={id_jag_result.expires_in}s")
            except Exception as e:
                logger.error(f"[ID-JAG] STEP 1 FAILED: {str(e)}", exc_info=True)
                
                # Try to extract Okta's error response for debugging
                try:
                    if hasattr(e, 'response') and hasattr(e.response, 'text'):
                        okta_error = e.response.text
                        logger.error(f"[ID-JAG] Okta error response: {okta_error}")
                    if hasattr(e, '__cause__'):
                        logger.error(f"[ID-JAG] Root cause: {e.__cause__}")
                except:
                    pass
                
                return None
            
            # STEP 2: Verify ID-JAG token (optional, for audit trail)
            logger.debug("[ID-JAG] STEP 2: Verifying ID-JAG token")
            try:
                verification_result = self.sdk_main.cross_app_access.verify_id_jag_token(
                    token=id_jag_result.access_token,
                    audience=id_jag_audience
                )
                
                if verification_result.valid:
                    logger.debug(f"[ID-JAG] STEP 2 SUCCESS: sub={verification_result.sub}")
                else:
                    logger.warning(f"[ID-JAG] STEP 2 warning: {verification_result.error}")
            except Exception as e:
                logger.debug(f"[ID-JAG] STEP 2 verification skipped: {e}")
            
            # STEP 3: Exchange ID-JAG for authorization server token (MCP access token)
            logger.debug(f"[ID-JAG] STEP 3: Exchanging ID-JAG for MCP token at {backend_name}")
            
            mcp_sdk = self._get_or_create_mcp_sdk(backend_name, target_auth_server_id)
            if not mcp_sdk:
                logger.error(f"Failed to create MCP SDK for {backend_name}")
                return None
            
            try:
                # Per okta-ai-sdk-proto 1.0.3 API
                auth_server_request = AuthServerTokenRequest(
                    id_jag_token=id_jag_result.access_token,
                    authorization_server_id=target_auth_server_id,
                    principal_id=self.agent_id.strip(),
                    private_jwk=self.agent_private_key
                )
                
                mcp_token_result = mcp_sdk.cross_app_access.exchange_id_jag_for_auth_server_token(
                    auth_server_request
                )
                logger.info(f"[ID-JAG] STEP 3 SUCCESS: MCP access_token expires_in={mcp_token_result.expires_in}s, scope={getattr(mcp_token_result, 'scope', 'N/A')}")
            except Exception as e:
                error_msg = str(e)
                if "timeout" in error_msg.lower():
                    logger.error(f"[ID-JAG] STEP 3 TIMEOUT: Okta server not responding")
                else:
                    logger.error(f"[ID-JAG] STEP 3 FAILED: {error_msg}", exc_info=True)
                return None
            
            # STEP 4: Return token info (verification done by backend MCP server)
            return {
                "access_token": mcp_token_result.access_token,
                "token_type": getattr(mcp_token_result, "token_type", "Bearer"),
                "expires_in": mcp_token_result.expires_in,
                "scope": getattr(mcp_token_result, "scope", scope_str)
            }
        
        except Exception as e:
            logger.error(f"[ID-JAG] Unexpected error: {str(e)}", exc_info=True)
            return None
    
    async def verify_mcp_token(
        self,
        token: str,
        backend_name: str,
        target_auth_server_id: str,
        audience: str = None
    ) -> Optional[Dict[str, Any]]:
        """
        Verify MCP access token validity at the target authorization server.
        
        STEP 4: Verify token before granting MCP server access
        
        Args:
            token: MCP access token to verify
            backend_name: Name of the backend MCP server
            target_auth_server_id: Authorization server ID at the target
            audience: Expected audience for the token (optional)
        
        Returns:
            Dict with token claims if valid, None if invalid
        """
        if not self.sdk_main:
            logger.error("ID-JAG SDK not configured for token verification")
            return None
        
        try:
            mcp_sdk = self._get_or_create_mcp_sdk(backend_name, target_auth_server_id)
            if not mcp_sdk:
                logger.error(f"Failed to create MCP SDK for verification")
                return None
            
            logger.debug(f"[ID-JAG] STEP 4: Verifying MCP token for {backend_name}")
            
            try:
                # Use SDK's token verification method
                verification_result = mcp_sdk.cross_app_access.verify_auth_server_token(
                    token=token,
                    authorization_server_id=target_auth_server_id,
                    audience=audience  # Optional audience validation
                )
                
                if verification_result.valid:
                    logger.info(f"[ID-JAG] STEP 4 SUCCESS: sub={verification_result.sub}, scope={verification_result.scope}")
                    logger.debug(f"[ID-JAG] Token claims: aud={verification_result.aud}, iss={verification_result.iss}")
                    
                    return {
                        "valid": True,
                        "sub": verification_result.sub,
                        "aud": verification_result.aud,
                        "iss": verification_result.iss,
                        "scope": verification_result.scope,
                        "exp": verification_result.exp,
                        "payload": verification_result.payload
                    }
                else:
                    logger.error(f"[ID-JAG] STEP 4 FAILED: Token verification error: {verification_result.error}")
                    return None
                    
            except Exception as e:
                logger.error(f"[ID-JAG] STEP 4 FAILED: {str(e)}", exc_info=True)
                return None
                
        except Exception as e:
            logger.error(f"[ID-JAG] Token verification failed: {e}")
            return None

"""
MCP Session Manager

Handles MCP session lifecycle per backend:
1. Create session on first request
2. Cache session ID per user per backend
3. Include session ID in all subsequent requests
4. Clean up on timeout

Session cache key: {user_id}:{backend_name}
"""

import logging
import httpx
import uuid
from typing import Optional, Dict, Tuple
from datetime import datetime, timedelta
import cachetools

logger = logging.getLogger(__name__)


class MCPSessionManager:
    """Manages MCP session creation and caching"""
    
    def __init__(self, session_ttl: int = 3600):
        """
        Initialize session manager.
        
        Args:
            session_ttl: Session TTL in seconds (default: 1 hour)
        """
        self.session_ttl = session_ttl
        # Cache: {user_id}:{backend_name} -> {session_id, created_at, expires_at}
        self.sessions = cachetools.TTLCache(
            maxsize=1000,
            ttl=session_ttl
        )
        logger.info(f"MCPSessionManager initialized with TTL={session_ttl}s")
    
    async def get_or_create_session(
        self,
        user_id: str,
        backend_name: str,
        backend_url: str,
        access_token: str
    ) -> Optional[str]:
        """
        Get existing session or create new one.
        
        Args:
            user_id: User identifier
            backend_name: Backend MCP server name
            backend_url: Backend MCP URL (should include /mcp endpoint)
            access_token: Access token for auth (if needed for initialize)
        
        Returns:
            Session ID if successful, None if failed
        """
        cache_key = f"{user_id}:{backend_name}"
        
        # Check cache first
        if cache_key in self.sessions:
            session_data = self.sessions[cache_key]
            logger.debug(
                f"Using cached session for {cache_key}: "
                f"{session_data['session_id'][:8]}..."
            )
            return session_data['session_id']
        
        # Create new session
        logger.info(f"Creating new MCP session for {cache_key}")
        session_id = await self._create_session(backend_url, access_token)
        
        if not session_id:
            logger.error(f"Failed to create session for {cache_key}")
            return None
        
        # Cache session
        self.sessions[cache_key] = {
            'session_id': session_id,
            'created_at': datetime.now(),
            'expires_at': datetime.now() + timedelta(seconds=self.session_ttl),
            'backend_url': backend_url
        }
        
        logger.info(
            f"Session created for {cache_key}: {session_id[:8]}... "
            f"(expires in {self.session_ttl}s)"
        )
        
        return session_id
    
    async def _create_session(
        self,
        backend_url: str,
        access_token: str
    ) -> Optional[str]:
        """
        Create new MCP session by sending initialize request.
        
        For stateless backends (like FastMCP servers), generates a synthetic session ID
        since the backend won't return Mcp-Session-Id header.
        
        Args:
            backend_url: Backend MCP URL
            access_token: Access token (may be needed for initialize)
        
        Returns:
            Session ID from response header, or generated ID for stateless backends
        """
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                headers = {
                    "Content-Type": "application/json",
                }
                # Include auth header even for initialize (some servers may require it)
                if access_token:
                    headers["Authorization"] = f"Bearer {access_token}"
                
                logger.debug(f"Initializing MCP session with {backend_url}")
                
                response = await client.post(
                    backend_url,
                    json={
                        "jsonrpc": "2.0",
                        "method": "initialize",
                        "params": {},
                        "id": str(uuid.uuid4())
                    },
                    headers=headers
                )
                
                if response.status_code != 200:
                    logger.error(
                        f"Initialize failed: {response.status_code} - {response.text}"
                    )
                    return None
                
                # Extract session ID from response header (case-insensitive)
                logger.debug(f"Initialize response headers: {dict(response.headers)}")
                session_id = response.headers.get("mcp-session-id") or response.headers.get("Mcp-Session-Id")
                
                # If backend doesn't return session ID (stateless), generate one
                if not session_id:
                    # Stateless backends (like FastMCP) don't track sessions
                    # Generate a synthetic ID for the gateway's internal tracking
                    session_id = str(uuid.uuid4())
                    logger.debug(
                        f"Backend did not return session ID - generated synthetic ID: {session_id[:8]}... "
                        "(backend is stateless, gateway will manage sessions)"
                    )
                else:
                    logger.debug(f"Session ID obtained from backend: {session_id[:8]}...")
                
                return session_id
        
        except Exception as e:
            logger.error(f"Error creating session: {e}", exc_info=True)
            return None
    
    async def terminate_session(
        self,
        user_id: str,
        backend_name: str,
        backend_url: str,
        session_id: str
    ) -> bool:
        """
        Terminate MCP session.
        
        Args:
            user_id: User identifier
            backend_name: Backend name
            backend_url: Backend MCP URL
            session_id: Session ID to terminate
        
        Returns:
            True if successful, False otherwise
        """
        cache_key = f"{user_id}:{backend_name}"
        
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                logger.debug(f"Terminating session {session_id[:8]}...")
                
                response = await client.delete(
                    backend_url,
                    headers={
                        "Mcp-Session-Id": session_id
                    }
                )
                
                if response.status_code in [200, 204]:
                    logger.info(f"Session terminated: {session_id[:8]}...")
                    # Remove from cache
                    if cache_key in self.sessions:
                        del self.sessions[cache_key]
                    return True
                else:
                    logger.warning(
                        f"Session terminate returned {response.status_code}: {response.text}"
                    )
                    return False
        
        except Exception as e:
            logger.error(f"Error terminating session: {e}")
            return False
    
    def invalidate_session(self, user_id: str, backend_name: str) -> None:
        """
        Invalidate cached session (e.g., after auth error).
        
        Args:
            user_id: User identifier
            backend_name: Backend name
        """
        cache_key = f"{user_id}:{backend_name}"
        if cache_key in self.sessions:
            session_id = self.sessions[cache_key]['session_id']
            logger.info(f"Invalidating session: {session_id[:8]}...")
            del self.sessions[cache_key]
    
    def get_session_stats(self) -> Dict[str, int]:
        """Get session cache statistics"""
        return {
            "active_sessions": len(self.sessions),
            "max_sessions": self.sessions.maxsize,
            "ttl_seconds": self.session_ttl
        }


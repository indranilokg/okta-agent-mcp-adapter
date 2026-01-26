"""
Token cache implementation using cachetools
Stores backend tokens with automatic TTL expiration
"""

import logging
from typing import Optional
from cachetools import TTLCache

logger = logging.getLogger(__name__)


class TokenCache:
    """
    In-memory token cache with TTL (Time To Live) expiration.
    
    Keys are formatted as: {user_id}:{backend_name}:{auth_server}
    Values are backend JWT tokens that auto-expire after ttl_seconds.
    """
    
    def __init__(self, max_size: int = 50000, ttl_seconds: int = 3600):
        """
        Initialize token cache.
        
        Args:
            max_size: Maximum number of tokens to cache
            ttl_seconds: Time to live for cached tokens (default 1 hour)
        """
        self.cache = TTLCache(maxsize=max_size, ttl=ttl_seconds)
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        logger.info(f"TokenCache initialized: max_size={max_size}, ttl={ttl_seconds}s")
    
    @staticmethod
    def _make_key(user_id: str, backend_name: str, auth_server: str = "") -> str:
        """
        Generate cache key from components.
        
        Args:
            user_id: User identifier (from token 'sub' claim)
            backend_name: Backend MCP server name
            auth_server: Authorization server ID (optional)
        
        Returns:
            Cache key string
        """
        if auth_server:
            return f"{user_id}:{backend_name}:{auth_server}"
        return f"{user_id}:{backend_name}"
    
    def get(self, user_id: str, backend_name: str, auth_server: str = "") -> Optional[str]:
        """
        Get cached backend token.
        
        Returns None if not found or expired (TTLCache auto-removes expired).
        
        Args:
            user_id: User identifier
            backend_name: Backend name
            auth_server: Authorization server ID (optional)
        
        Returns:
            Cached token string or None
        """
        key = self._make_key(user_id, backend_name, auth_server)
        token = self.cache.get(key)
        
        if token:
            logger.debug(f"Cache HIT: {key}")
        else:
            logger.debug(f"Cache MISS: {key}")
        
        return token
    
    def set(self, user_id: str, backend_name: str, token: str, 
            auth_server: str = "", ttl_seconds: Optional[int] = None) -> None:
        """
        Cache a backend token.
        
        Args:
            user_id: User identifier
            backend_name: Backend name
            token: Backend JWT token to cache
            auth_server: Authorization server ID (optional)
            ttl_seconds: Custom TTL for this token (uses default if not provided)
        """
        key = self._make_key(user_id, backend_name, auth_server)
        
        # Note: cachetools TTLCache doesn't support per-item TTL in standard usage
        # The ttl_seconds parameter is accepted but not used in current implementation
        # For production, consider migrating to Redis for per-item TTL support
        
        self.cache[key] = token
        logger.info(f"Token cached: {key} (TTL: {self.ttl_seconds}s)")
    
    def invalidate(self, user_id: str, backend_name: str = "", auth_server: str = "") -> None:
        """
        Invalidate cached tokens for a user.
        
        Args:
            user_id: User identifier
            backend_name: Optional - specific backend to invalidate
            auth_server: Optional - specific auth server to invalidate
        """
        if backend_name:
            # Invalidate specific backend token
            key = self._make_key(user_id, backend_name, auth_server)
            if key in self.cache:
                del self.cache[key]
                logger.info(f"Token invalidated: {key}")
        else:
            # Invalidate all tokens for user
            keys_to_delete = [k for k in self.cache.keys() if k.startswith(user_id)]
            for key in keys_to_delete:
                del self.cache[key]
            logger.info(f"All tokens invalidated for user: {user_id} ({len(keys_to_delete)} tokens)")
    
    def stats(self) -> dict:
        """
        Get cache statistics.
        
        Returns:
            Dictionary with cache stats
        """
        return {
            "current_size": len(self.cache),
            "max_size": self.max_size,
            "usage_percent": (len(self.cache) / self.max_size) * 100,
            "ttl_seconds": self.ttl_seconds
        }
    
    def clear(self) -> None:
        """Clear all cached tokens."""
        self.cache.clear()
        logger.info("Token cache cleared")


"""
Admin Authentication Module

Handles JWT token generation and validation for admin API access.
"""

import logging
import datetime
from typing import Optional, Dict, Any
from jose import jwt, JWTError
import os

logger = logging.getLogger(__name__)

# Admin JWT configuration
ADMIN_SECRET_KEY = os.getenv("ADMIN_JWT_SECRET", "change-me-in-production-okta-admin-secret")
ADMIN_TOKEN_EXPIRATION = int(os.getenv("ADMIN_TOKEN_EXPIRATION", "3600"))  # 1 hour
ALGORITHM = "HS256"

# Hardcoded admin credentials
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")


class AdminAuthError(Exception):
    """Raised when admin authentication fails"""
    pass


def generate_admin_token(username: str) -> Dict[str, Any]:
    """
    Generate JWT token for admin user.
    
    Args:
        username: Admin username
    
    Returns:
        Dict with token and expiration info
    """
    # Calculate expiration time
    expires = datetime.datetime.utcnow() + datetime.timedelta(seconds=ADMIN_TOKEN_EXPIRATION)
    
    # Create JWT payload
    payload = {
        "username": username,
        "role": "admin",
        "exp": expires,
        "iat": datetime.datetime.utcnow(),
    }
    
    try:
        # Encode token
        token = jwt.encode(payload, ADMIN_SECRET_KEY, algorithm=ALGORITHM)
        logger.info(f"Generated admin token for user: {username}")
        
        return {
            "access_token": token,
            "token_type": "bearer",
            "expires_in": ADMIN_TOKEN_EXPIRATION,
        }
    except Exception as e:
        logger.error(f"Failed to generate admin token: {e}")
        raise AdminAuthError("Failed to generate token")


def verify_admin_token(token: str) -> Dict[str, Any]:
    """
    Verify and decode JWT token.
    
    Args:
        token: JWT token to verify
    
    Returns:
        Token payload if valid
    
    Raises:
        AdminAuthError: If token is invalid or expired
    """
    try:
        payload = jwt.decode(token, ADMIN_SECRET_KEY, algorithms=[ALGORITHM])
        
        # Verify admin role
        if payload.get("role") != "admin":
            raise AdminAuthError("Token does not have admin role")
        
        return payload
    except JWTError as e:
        logger.warning(f"Invalid admin token: {e}")
        raise AdminAuthError("Invalid or expired token")
    except Exception as e:
        logger.error(f"Token verification error: {e}")
        raise AdminAuthError("Token verification failed")


def validate_credentials(username: str, password: str) -> bool:
    """
    Validate admin credentials.
    
    Args:
        username: Admin username
        password: Admin password
    
    Returns:
        True if credentials are valid
    """
    is_valid = username == ADMIN_USERNAME and password == ADMIN_PASSWORD
    
    if not is_valid:
        logger.warning(f"Failed admin login attempt for user: {username}")
    else:
        logger.info(f"Successful admin login: {username}")
    
    return is_valid

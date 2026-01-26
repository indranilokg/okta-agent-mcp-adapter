"""
Logging setup for MCP Gateway
"""

import logging
import os
from typing import Optional


def setup_logging(log_level: Optional[str] = None) -> None:
    """
    Configure logging for the gateway.
    
    Args:
        log_level: Log level (DEBUG, INFO, WARNING, ERROR)
    """
    if log_level is None:
        log_level = os.getenv("LOG_LEVEL", "INFO")
    
    # Create logger
    logger = logging.getLogger()
    logger.setLevel(getattr(logging, log_level.upper()))
    
    # Console handler
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    handler.setFormatter(formatter)
    
    # Add handler if not already present
    if not logger.handlers:
        logger.addHandler(handler)
    
    # Suppress noisy loggers
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("asyncio").setLevel(logging.WARNING)
    
    logger.info(f"Logging configured: level={log_level}")


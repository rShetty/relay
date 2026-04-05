"""
Database-backed storage initialization for MCP Gateway

This module provides factory functions to create database-backed
OAuth provider and token store.
"""

import logging
from auth.oauth import JWTManager
from auth.database_oauth import DatabaseOAuthProvider, DatabaseTokenStore
from auth.token_store import AbstractTokenStore

logger = logging.getLogger(__name__)


def create_database_oauth_provider(
    secret_key: str,
    access_token_expire_minutes: int = 30,
    refresh_token_expire_days: int = 7,
    enable_demo_user: bool = False,
) -> DatabaseOAuthProvider:
    """Create a database-backed OAuth provider."""
    jwt_manager = JWTManager(
        secret_key=secret_key,
        access_token_expire_minutes=access_token_expire_minutes,
        refresh_token_expire_days=refresh_token_expire_days,
    )
    
    provider = DatabaseOAuthProvider(
        jwt_manager=jwt_manager,
        enable_demo_user=enable_demo_user,
    )
    
    logger.info("Created database-backed OAuth provider")
    return provider


def create_database_token_store() -> DatabaseTokenStore:
    """Create a database-backed token store for third-party tokens."""
    store = DatabaseTokenStore()
    logger.info("Created database-backed token store")
    return store
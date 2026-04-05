"""
Database-backed OAuth Provider

This module provides a drop-in replacement for the in-memory OAuthProvider
that uses SQLite for persistent storage.
"""

import secrets
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any
from auth.oauth import OAuthProvider, AuthorizationCode, ClientRegistration, User, TokenPair
from auth import database as db

logger = logging.getLogger(__name__)


class DatabaseOAuthProvider(OAuthProvider):
    """
    OAuth Provider backed by SQLite database.
    
    This replaces the in-memory dictionaries with database operations.
    """
    
    def __init__(self, jwt_manager, code_expire_minutes=10, enable_demo_user=False,
                 demo_user_id="demo_user_001", demo_username="demo"):
        # Initialize database
        db.init_db()
        
        # Call parent init (for JWT manager)
        super().__init__(
            jwt_manager=jwt_manager,
            code_expire_minutes=code_expire_minutes,
            enable_demo_user=False,  # We handle demo separately
            demo_user_id=demo_user_id,
            demo_username=demo_username,
        )
        
        # Add demo user to database
        if enable_demo_user:
            self._add_demo_user(demo_user_id, demo_username)
    
    def _add_demo_user(self, user_id: str, username: str) -> None:
        """Add demo user to database if not exists."""
        # Demo user credentials will be created on first access
        pass
    
    # -------------------------------------------------------------------------
    # Client Management - Database-backed
    # -------------------------------------------------------------------------
    
    def register_client(
        self,
        client_name: str,
        redirect_uris: list[str],
        is_confidential: bool = True,
    ) -> ClientRegistration:
        """Register a new OAuth client."""
        client_id = f"client_{secrets.token_urlsafe(16)}"
        client_secret = secrets.token_urlsafe(24) if is_confidential else None
        
        client = ClientRegistration(
            client_id=client_id,
            client_name=client_name,
            redirect_uris=redirect_uris,
            is_confidential=is_confidential,
        )
        
        # Save to database
        db.save_oauth_client(
            client_id=client_id,
            client_name=client_name,
            client_secret=client_secret,
            redirect_uris=redirect_uris,
            is_confidential=is_confidential,
        )
        
        logger.info(f"Registered OAuth client: {client_name} ({client_id[:12]}...)")
        
        # Store secret in client for later use (not persisted in client object)
        client._client_secret = client_secret
        
        return client
    
    def get_client(self, client_id: str) -> Optional[ClientRegistration]:
        """Get client by ID."""
        client_data = db.get_oauth_client(client_id)
        if not client_data:
            return None
        
        return ClientRegistration(
            client_id=client_data["client_id"],
            client_name=client_data["client_name"],
            redirect_uris=client_data["redirect_uris"],
            is_confidential=client_data["is_confidential"],
        )
    
    def validate_redirect_uri(self, client_id: str, redirect_uri: str) -> bool:
        """Validate redirect URI."""
        client_data = db.get_oauth_client(client_id)
        if not client_data:
            return False
        
        for registered in client_data["redirect_uris"]:
            if registered == redirect_uri:
                return True
        return False
    
    def validate_client_secret(self, client_id: str, client_secret: str) -> bool:
        """Validate client secret."""
        client_data = db.get_oauth_client_by_secret(client_id, client_secret)
        return client_data is not None
    
    # -------------------------------------------------------------------------
    # Authorization Code Management - Database-backed
    # -------------------------------------------------------------------------
    
    def create_authorization_code(
        self,
        client_id: str,
        redirect_uri: str,
        code_challenge: str = None,
        code_challenge_method: str = "S256",
        scope: Optional[str] = "mcp:tools",
        user_id: Optional[str] = None,
    ) -> str:
        """Create an authorization code for the authorization endpoint."""
        if user_id is None:
            raise ValueError("user_id is required — demo user is disabled")
        
        code = secrets.token_urlsafe(32)
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=self.code_expire_minutes)
        
        # Save to database
        db.save_auth_code(
            code=code,
            client_id=client_id,
            user_id=user_id,
            redirect_uri=redirect_uri,
            scope=scope,
            expires_at=expires_at.isoformat(),
        )
        
        return code
    
    def validate_authorization_code(
        self,
        code: str,
        client_id: str,
        redirect_uri: str,
    ) -> Optional[Dict[str, Any]]:
        """Validate and consume authorization code."""
        code_data = db.get_auth_code(code)
        if not code_data:
            return None
        
        if code_data["client_id"] != client_id:
            return None
        
        if code_data["redirect_uri"] != redirect_uri:
            return None
        
        # Delete code after use (one-time use)
        db.delete_auth_code(code)
        
        return {
            "user_id": code_data["user_id"],
            "client_id": code_data["client_id"],
            "scope": code_data["scope"],
        }
    
    # -------------------------------------------------------------------------
    # Token Management - Database-backed
    # -------------------------------------------------------------------------
    
    def _create_token_pair(
        self,
        client_id: str,
        user_id: str,
        scope: Optional[str] = None,
        include_refresh: bool = True,
    ) -> TokenPair:
        """Create access and refresh token pair."""
        access_token = self.jwt.create_access_token(
            user_id=user_id,
            client_id=client_id,
            scope=scope or "mcp:tools",
        )
        
        refresh_token = None
        if include_refresh:
            refresh_token = self.jwt.create_refresh_token(
                user_id=user_id,
                client_id=client_id,
                scope=scope or "mcp:tools",
            )
        
        # Save to database
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=self.jwt.access_token_expire_minutes * 60)
        db.save_user_credential(
            user_id=user_id,
            client_id=client_id,
            access_token=access_token,
            refresh_token=refresh_token,
            expires_at=expires_at.isoformat(),
            scope=scope,
        )
        
        return TokenPair(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=self.jwt.access_token_expire_minutes * 60,
            token_type="Bearer",
            scope=scope or "mcp:tools",
        )
    
    def validate_access_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Validate access token."""
        # Use parent's JWT validation
        payload = self.jwt.decode_token(token)
        if not payload:
            return None
        
        # Check if revoked using database
        if db.is_token_revoked(payload.jti):
            return None
        
        # Get client to verify it still exists
        client = self.get_client(payload.client_id)
        if not client:
            return None
        
        return {
            "user_id": payload.sub,
            "client_id": payload.client_id,
            "scope": payload.scope,
        }
    
    def refresh_access_token(self, refresh_token: str, client_id: Optional[str] = None) -> Optional[TokenPair]:
        """Refresh access token."""
        payload = self.jwt.decode_token(refresh_token)
        if not payload:
            return None
        
        if db.is_token_revoked(payload.jti):
            return None
        
        if client_id and payload.client_id != client_id:
            logger.warning(f"Client ID mismatch in refresh token")
            return None
        
        return self._create_token_pair(
            client_id=payload.client_id,
            user_id=payload.sub,
            scope=payload.scope,
        )
    
    def revoke_token(self, token: str) -> bool:
        """Revoke a token."""
        payload = self.jwt.decode_token(token)
        if not payload:
            return False
        
        # payload.exp is already a datetime object
        expires_at = payload.exp if isinstance(payload.exp, datetime) else datetime.fromtimestamp(payload.exp, timezone.utc)
        
        db.revoke_token(payload.jti, expires_at.isoformat())
        
        return True
    
    def exchange_code_for_token(
        self,
        code: str,
        code_verifier: str,
        client_id: str,
        redirect_uri: str,
    ):
        """Exchange authorization code for tokens."""
        auth_code = self.validate_authorization_code(code, client_id, redirect_uri)
        if not auth_code:
            logger.warning(f"Authorization code validation failed: {code[:12]}...")
            return None
        
        # Create token pair for this user
        return self._create_token_pair(
            client_id=auth_code["client_id"],
            user_id=auth_code["user_id"],
            scope=auth_code.get("scope", "mcp:tools"),
        )


# -----------------------------------------------------------------------------
# Database-backed Connector Token Store
# -----------------------------------------------------------------------------

class DatabaseTokenStore:
    """
    Database-backed token store for connector (third-party) tokens.
    
    This replaces the in-memory token store with SQLite persistence.
    """
    
    def __init__(self):
        # Ensure database is initialized
        db.init_db()
    
    async def set_token(
        self,
        user_id: str,
        connector_name: str,
        token: str,
        token_type: str = "Bearer",
        refresh_token: Optional[str] = None,
        expires_at: Optional[str] = None,
        metadata: Optional[Dict] = None,
    ) -> None:
        """Store a connector token for a user."""
        db.save_connector_token(
            user_id=user_id,
            connector_name=connector_name,
            token=token,
            token_type=token_type,
            refresh_token=refresh_token,
            expires_at=expires_at,
            metadata=metadata,
        )
        logger.info(f"Stored token for user {user_id}, connector {connector_name}")
    
    async def get_token(self, user_id: str, connector_name: str) -> Optional[str]:
        """Get connector token for a user."""
        return db.get_connector_token(user_id, connector_name)
    
    async def get_token_full(self, user_id: str, connector_name: str) -> Optional[Dict[str, Any]]:
        """Get full connector token info."""
        return db.get_connector_token_full(user_id, connector_name)
    
    async def delete_token(self, user_id: str, connector_name: str) -> bool:
        """Delete connector token."""
        result = db.delete_connector_token(user_id, connector_name)
        if result:
            logger.info(f"Deleted token for user {user_id}, connector {connector_name}")
        return result
    
    async def list_connectors_for_user(self, user_id: str) -> List[str]:
        """List all connectors with tokens for a user."""
        return db.list_user_connectors(user_id)


# Need to import List for type hints
from typing import List
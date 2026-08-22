"""
OAuth 2.1 Authentication for MCP Gateway

Implements OAuth 2.1 with PKCE (Proof Key for Code Exchange) for secure
authentication of MCP clients like Cursor, Claude Code, etc.

Flow:
1. Client registers with redirect_uri and obtains client_id
2. Client redirects user to /oauth/authorize with code_challenge
3. User authenticates and authorizes
4. Gateway redirects back with authorization code
5. Client exchanges code for tokens at /oauth/token with code_verifier
6. Client uses access_token in Authorization header for MCP requests
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

from jose import JWTError, jwt
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Models
# -----------------------------------------------------------------------------

class ClientRegistration(BaseModel):
    """OAuth client registration details."""

    client_id: str
    client_name: str
    redirect_uris: list[str]
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    is_confidential: bool = True
    allowed_scopes: list[str] = Field(default_factory=lambda: ["mcp:tools", "mcp:resources"])


class AuthorizationCode(BaseModel):
    """OAuth 2.1 authorization code with PKCE binding."""

    code: str
    client_id: str
    redirect_uri: str
    code_challenge: str
    code_challenge_method: str = "S256"
    scope: str
    user_id: str
    expires_at: datetime
    used: bool = False


class TokenPair(BaseModel):
    """Access and refresh token pair."""

    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int
    scope: str


class TokenPayload(BaseModel):
    """JWT token payload."""

    sub: str  # user_id
    client_id: str
    scope: str
    exp: datetime
    iat: datetime
    jti: str  # unique token ID for revocation


@dataclass
class User:
    """Authenticated user."""

    user_id: str
    username: str
    email: Optional[str] = None
    scopes: list[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# -----------------------------------------------------------------------------
# PKCE Helpers
# -----------------------------------------------------------------------------

def generate_code_verifier(length: int = 128) -> str:
    """
    Generate a cryptographically random code verifier.

    Per RFC 7636, the code verifier must be:
    - 43-128 characters long
    - Contain only unreserved characters: A-Z, a-z, 0-9, -, ., _, ~
    """
    if length < 43 or length > 128:
        raise ValueError("Code verifier length must be between 43 and 128")
    
    charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
    random_bytes = secrets.token_bytes(length)
    return "".join(charset[b % len(charset)] for b in random_bytes)


def generate_code_challenge(verifier: str, method: str = "S256") -> str:
    """
    Generate code challenge from verifier.

    S256: code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
    plain: code_challenge = code_verifier
    """
    if method == "plain":
        return verifier
    elif method == "S256":
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    else:
        raise ValueError(f"Unsupported challenge method: {method}")


def verify_code_verifier(verifier: str, challenge: str, method: str = "S256") -> bool:
    """Verify that the code verifier matches the challenge."""
    expected_challenge = generate_code_challenge(verifier, method)
    return secrets.compare_digest(expected_challenge, challenge)


# -----------------------------------------------------------------------------
# JWT Token Management
# -----------------------------------------------------------------------------

class JWTManager:
    """Manages JWT token creation, validation, and revocation."""

    def __init__(
        self,
        secret_key: str,
        algorithm: str = "HS256",
        access_token_expire_minutes: int = 30,
        refresh_token_expire_days: int = 7,
        public_key: Optional[str] = None,
    ):
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.public_key = public_key or secret_key
        self.access_token_expire_minutes = access_token_expire_minutes
        self.refresh_token_expire_days = refresh_token_expire_days
        # jti -> expiry timestamp; cleaned up lazily on decode
        self._revoked_tokens: Dict[str, float] = {}
        # Optional Redis sync client for distributed revocation
        self._redis: Optional[Any] = None

    # ------------------------------------------------------------------
    # Redis integration (optional — falls back to in-memory gracefully)
    # ------------------------------------------------------------------

    def configure_redis(self, redis_url: str) -> None:
        """
        Configure a Redis connection for distributed JWT revocation.

        When set, ``revoke_token`` writes to Redis in addition to the
        in-memory dict, and ``is_revoked`` checks Redis as a secondary
        source.  If Redis becomes unavailable the system degrades
        gracefully to in-memory-only (fail-open behaviour).

        Args:
            redis_url: Redis connection URL, e.g. ``redis://localhost:6379``.
        """
        try:
            import redis as redis_lib
            client = redis_lib.from_url(redis_url, decode_responses=True, socket_timeout=2)
            client.ping()
            self._redis = client
            logger.info("JWTManager: Redis revocation store connected")
        except Exception as exc:
            logger.warning(
                f"JWTManager: Redis not available for token revocation — "
                f"using in-memory fallback. ({exc})"
            )

    def create_access_token(
        self,
        user_id: str,
        client_id: str,
        scope: str,
        expires_delta: Optional[timedelta] = None,
    ) -> str:
        """Create a JWT access token."""
        if expires_delta is None:
            expires_delta = timedelta(minutes=self.access_token_expire_minutes)
        
        now = datetime.now(timezone.utc)
        expire = now + expires_delta
        jti = secrets.token_urlsafe(16)
        
        payload = {
            "sub": user_id,
            "client_id": client_id,
            "scope": scope,
            "exp": expire,
            "iat": now,
            "jti": jti,
        }
        
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

    def create_refresh_token(
        self,
        user_id: str,
        client_id: str,
        scope: str,
    ) -> str:
        """Create a JWT refresh token."""
        now = datetime.now(timezone.utc)
        expire = now + timedelta(days=self.refresh_token_expire_days)
        jti = secrets.token_urlsafe(16)
        
        payload = {
            "sub": user_id,
            "client_id": client_id,
            "scope": scope,
            "exp": expire,
            "iat": now,
            "jti": jti,
            "refresh": True,
        }
        
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

    def decode_token(self, token: str) -> Optional[TokenPayload]:
        """Decode and validate a JWT token."""
        try:
            payload = jwt.decode(
                token,
                self.public_key,
                algorithms=[self.algorithm],
            )
            
            # Purge expired in-memory entries opportunistically, then check revocation
            jti = payload.get("jti")
            now_ts = time.time()
            self._revoked_tokens = {
                k: v for k, v in self._revoked_tokens.items() if v > now_ts
            }
            if jti and self.is_revoked(jti):
                logger.warning(f"Attempted use of revoked token: {jti[:8]}...")
                return None
            
            return TokenPayload(
                sub=payload["sub"],
                client_id=payload["client_id"],
                scope=payload["scope"],
                exp=datetime.fromtimestamp(payload["exp"], tz=timezone.utc),
                iat=datetime.fromtimestamp(payload["iat"], tz=timezone.utc),
                jti=jti,
            )
        except JWTError as e:
            logger.debug(f"JWT decode failed: {e}")
            return None

    def revoke_token(self, jti: str, ttl_seconds: Optional[float] = None) -> None:
        """
        Revoke a token by its JTI.

        Writes to the in-memory dict *and* to Redis (if configured) so
        revocations are shared across multiple gateway instances.
        TTL defaults to the refresh-token lifetime so the entry auto-expires.
        """
        if ttl_seconds is None:
            ttl_seconds = self.refresh_token_expire_days * 86400
        self._revoked_tokens[jti] = time.time() + ttl_seconds
        if self._redis is not None:
            try:
                self._redis.setex(f"jwt_revoked:{jti}", int(ttl_seconds), "1")
            except Exception as exc:
                logger.warning(
                    f"Redis revocation write failed (in-memory fallback active): {exc}"
                )
        logger.info(f"Token revoked: {jti[:8]}...")

    def is_revoked(self, jti: str) -> bool:
        """
        Return True if *jti* has been revoked.

        Checks in-memory first (fast path), then Redis when configured.
        A Redis failure is treated as *not-revoked* (fail-open) to avoid
        locking users out when Redis is temporarily unavailable.
        """
        now_ts = time.time()
        entry = self._revoked_tokens.get(jti)
        if entry is not None and entry > now_ts:
            return True
        if self._redis is not None:
            try:
                return bool(self._redis.exists(f"jwt_revoked:{jti}"))
            except Exception as exc:
                logger.warning(f"Redis revocation check failed (fail-open): {exc}")
        return False


# -----------------------------------------------------------------------------
# OAuth Provider
# -----------------------------------------------------------------------------

class OAuthProvider:
    """
    Complete OAuth 2.1 provider implementation.

    Handles client registration, authorization codes, token issuance,
    and token validation with PKCE support.
    """

    def __init__(
        self,
        jwt_manager: JWTManager,
        code_expire_minutes: int = 10,
        enable_demo_user: bool = True,
        demo_user_id: str = "demo_user_001",
        demo_username: str = "demo",
    ):
        self.jwt = jwt_manager
        self.code_expire_minutes = code_expire_minutes
        self._enable_demo_user = enable_demo_user
        
        # In-memory stores (replace with Redis/DB in production)
        self._clients: Dict[str, ClientRegistration] = {}
        self._auth_codes: Dict[str, AuthorizationCode] = {}
        self._users: Dict[str, User] = {}
        
        # Demo user for POC - configurable
        if enable_demo_user:
            self._demo_user = User(
                user_id=demo_user_id,
                username=demo_username,
                email="demo@mcp-gateway.local",
                scopes=["mcp:tools", "mcp:resources"],
            )
            self._users[self._demo_user.user_id] = self._demo_user

    # -------------------------------------------------------------------------
    # Client Management
    # -------------------------------------------------------------------------

    def register_client(
        self,
        client_name: str,
        redirect_uris: list[str],
        is_confidential: bool = True,
    ) -> ClientRegistration:
        """Register a new OAuth client."""
        client_id = f"client_{secrets.token_urlsafe(16)}"
        
        client = ClientRegistration(
            client_id=client_id,
            client_name=client_name,
            redirect_uris=redirect_uris,
            is_confidential=is_confidential,
        )
        
        self._clients[client_id] = client
        logger.info(f"Registered OAuth client: {client_name} ({client_id[:12]}...)")
        
        return client

    def get_client(self, client_id: str) -> Optional[ClientRegistration]:
        """Get client by ID."""
        return self._clients.get(client_id)

    def validate_redirect_uri(self, client_id: str, redirect_uri: str) -> bool:
        """Validate that redirect_uri is registered for the client."""
        client = self._clients.get(client_id)
        if not client:
            return False
        
        # Exact match only — wildcard redirect URIs are prohibited by OAuth
        # security best practices (RFC 6749 §3.1.2, OAuth 2.0 Security BCP).
        for registered in client.redirect_uris:
            if registered == redirect_uri:
                return True

        return False

    # -------------------------------------------------------------------------
    # Authorization Code Flow
    # -------------------------------------------------------------------------

    def create_authorization_code(
        self,
        client_id: str,
        redirect_uri: str,
        code_challenge: str,
        code_challenge_method: str,
        scope: str,
        user_id: Optional[str] = None,
    ) -> str:
        """
        Create an authorization code for the authorization endpoint.

        Called after user authenticates and consents to the scope.
        """
        # Use demo user if no user_id provided (for POC)
        if user_id is None:
            if self._enable_demo_user and hasattr(self, '_demo_user'):
                user_id = self._demo_user.user_id
            else:
                raise ValueError("user_id required when demo user is disabled")
        
        code = secrets.token_urlsafe(32)
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=self.code_expire_minutes)
        
        auth_code = AuthorizationCode(
            code=code,
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            scope=scope,
            user_id=user_id,
            expires_at=expires_at,
        )
        
        self._auth_codes[code] = auth_code
        logger.debug(f"Created auth code for client {client_id[:12]}..., expires in {self.code_expire_minutes}m")
        
        return code

    def exchange_code_for_token(
        self,
        code: str,
        code_verifier: str,
        client_id: str,
        redirect_uri: str,
    ) -> Optional[TokenPair]:
        """
        Exchange authorization code for tokens at the token endpoint.

        Validates:
        - Code exists and not expired
        - Code not already used (one-time use)
        - PKCE verifier matches challenge
        - Client ID and redirect URI match
        """
        auth_code = self._auth_codes.get(code)
        
        if not auth_code:
            logger.warning(f"Authorization code not found: {code[:12]}...")
            return None
        
        # Check expiration
        if datetime.now(timezone.utc) > auth_code.expires_at:
            logger.warning(f"Authorization code expired: {code[:12]}...")
            del self._auth_codes[code]
            return None
        
        # Check if already used
        if auth_code.used:
            logger.warning(f"Authorization code already used: {code[:12]}...")
            # Security: invalidate all tokens for this code
            return None
        
        # Validate client_id
        if auth_code.client_id != client_id:
            logger.warning(f"Client ID mismatch for code {code[:12]}...")
            return None
        
        # Validate redirect_uri
        if auth_code.redirect_uri != redirect_uri:
            logger.warning(f"Redirect URI mismatch for code {code[:12]}...")
            return None
        
        # Verify PKCE
        if not verify_code_verifier(
            code_verifier,
            auth_code.code_challenge,
            auth_code.code_challenge_method,
        ):
            logger.warning(f"PKCE verification failed for code {code[:12]}...")
            return None
        
        # Mark code as used
        auth_code.used = True
        
        # Create tokens
        access_token = self.jwt.create_access_token(
            user_id=auth_code.user_id,
            client_id=client_id,
            scope=auth_code.scope,
        )
        refresh_token = self.jwt.create_refresh_token(
            user_id=auth_code.user_id,
            client_id=client_id,
            scope=auth_code.scope,
        )
        
        logger.info(f"Token issued for user {auth_code.user_id}, client {client_id[:12]}...")
        
        return TokenPair(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=self.jwt.access_token_expire_minutes * 60,
            scope=auth_code.scope,
        )

    def refresh_access_token(
        self,
        refresh_token: str,
        client_id: str,
    ) -> Optional[TokenPair]:
        """Refresh an access token using a refresh token."""
        payload = self.jwt.decode_token(refresh_token)
        
        if not payload:
            return None
        
        if payload.client_id != client_id:
            logger.warning(f"Client ID mismatch in refresh token")
            return None
        
        # Create new tokens
        new_access_token = self.jwt.create_access_token(
            user_id=payload.sub,
            client_id=client_id,
            scope=payload.scope,
        )
        new_refresh_token = self.jwt.create_refresh_token(
            user_id=payload.sub,
            client_id=client_id,
            scope=payload.scope,
        )
        
        # Revoke old refresh token
        self.jwt.revoke_token(payload.jti)
        
        return TokenPair(
            access_token=new_access_token,
            refresh_token=new_refresh_token,
            expires_in=self.jwt.access_token_expire_minutes * 60,
            scope=payload.scope,
        )

    def revoke_token(self, token: str) -> bool:
        """Revoke an access or refresh token."""
        payload = self.jwt.decode_token(token)
        if payload:
            self.jwt.revoke_token(payload.jti)
            return True
        return False

    def _create_token_pair(
        self,
        client_id: str,
        user_id: str,
        scope: str,
    ) -> TokenPair:
        """
        Directly issue a token pair without going through the auth code flow.

        Used for the API-key creation endpoint where a full OAuth round-trip is
        not appropriate (CLI / programmatic access).
        """
        access_token = self.jwt.create_access_token(
            user_id=user_id,
            client_id=client_id,
            scope=scope,
        )
        refresh_token = self.jwt.create_refresh_token(
            user_id=user_id,
            client_id=client_id,
            scope=scope,
        )
        return TokenPair(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=self.jwt.access_token_expire_minutes * 60,
            scope=scope,
        )

    # -------------------------------------------------------------------------
    # User Management
    # -------------------------------------------------------------------------

    def authenticate_user(
        self,
        username: str,
        password: str,
    ) -> Optional[User]:
        """
        Authenticate a user.

        Delegates to the database-backed user store. Returns None on
        invalid credentials.
        """
        return None  # DatabaseOAuthProvider overrides this

    def get_user(self, user_id: str) -> Optional[User]:
        """Get user by ID."""
        return self._users.get(user_id)

    # -------------------------------------------------------------------------
    # Token Validation (for FastAPI middleware)
    # -------------------------------------------------------------------------

    def validate_access_token(
        self,
        token: str,
        required_scopes: Optional[list[str]] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Validate an access token and return user info.

        Used by FastAPI Depends() to authenticate requests.
        """
        payload = self.jwt.decode_token(token)
        if not payload:
            return None
        
        # Check scope if required
        if required_scopes:
            token_scopes = set(payload.scope.split())
            if not all(s in token_scopes for s in required_scopes):
                logger.debug(f"Token missing required scopes: {required_scopes}")
                return None
        
        return {
            "user_id": payload.sub,
            "client_id": payload.client_id,
            "scope": payload.scope,
            "jti": payload.jti,
        }


# -----------------------------------------------------------------------------
# FastAPI Integration
# -----------------------------------------------------------------------------

def create_oauth_provider(
    secret_key: str,
    access_token_expire_minutes: int = 30,
    refresh_token_expire_days: int = 7,
) -> OAuthProvider:
    """Factory function to create an OAuth provider."""
    jwt_manager = JWTManager(
        secret_key=secret_key,
        access_token_expire_minutes=access_token_expire_minutes,
        refresh_token_expire_days=refresh_token_expire_days,
    )
    return OAuthProvider(jwt_manager=jwt_manager)

"""
Relay Server

The main MCP server that accepts connections from MCP clients (Cursor, Claude Code)
and routes requests to backend services through OAuth authentication.

Architecture:
    [MCP Client] --(OAuth + MCP)--> [Gateway Server] --(MCP/API)--> [Backend Services]

Features:
- OAuth 2.1 with PKCE for client authentication
- Rate limiting and security middleware
- Dynamic backend discovery and tool aggregation
- Audit logging
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from fastapi import FastAPI, HTTPException, Depends, Request, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from starlette.middleware.base import BaseHTTPMiddleware
from jinja2 import Environment, FileSystemLoader

from config.settings import (
    RelayConfig,
    get_config,
    BACKEND_DEFINITIONS,
    ROUTING_CONFIG,
    OAuthSettings,
    SecuritySettings,
    BackendSettings,
    ServerSettings,
)
from auth.oauth import (
    OAuthProvider, 
    create_oauth_provider,
    generate_code_verifier,
    generate_code_challenge,
)
from auth.oauth_providers import create_oauth_provider as create_connector_oauth_provider
from security.middleware import (
    SecurityContext, 
    RateLimiter, 
    InputValidator, 
    AuditLogger,
    IPRestrictions,
)
from backends.manager import (
    BackendManager, 
    BackendDefinition, 
    BackendType,
    BackendStatus,
)
from connectors import (
    ConnectorRegistry,
    initialize_connectors,
    get_registry,
)
from auth.token_store import get_token_store, set_token_store, AbstractTokenStore

logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Request ID Middleware
# -----------------------------------------------------------------------------

class RequestIDMiddleware(BaseHTTPMiddleware):
    """
    Injects a unique request ID into every request/response.

    - Respects an existing ``X-Request-ID`` header from the caller (for
      distributed tracing correlation).
    - Falls back to a freshly generated UUID4 when no caller ID is present.
    - Echoes the final ID back in the ``X-Request-ID`` response header.
    - Stores the ID on ``request.state.request_id`` so endpoint handlers and
      other middleware can log it.
    """

    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request.state.request_id = request_id
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response


# -----------------------------------------------------------------------------
# Application State
# -----------------------------------------------------------------------------

from auth.oauth_providers import OAuthProvider as ConnectorOAuthProvider

@dataclass
class AppState:
    """Global application state."""
    config: RelayConfig
    oauth: OAuthProvider
    connector_oauth: ConnectorOAuthProvider
    security: SecurityContext
    backends: BackendManager
    connectors: ConnectorRegistry
    started_at: datetime = None

    def __post_init__(self):
        self.started_at = datetime.now(timezone.utc)


state: Optional[AppState] = None


def _get_state() -> AppState:
    """Return the global AppState, raising 503 if the server is not yet ready."""
    if state is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=503, detail="Server not ready")
    return state


def _create_app_state_sync(config: RelayConfig) -> AppState:
    """
    Create AppState synchronously for standalone MCP server mode.
    
    This mirrors the lifespan initialization but without async/await.
    Used when running MCP server without the FastAPI server.
    """
    global state
    
    if state is not None:
        return state
    
    logger.info("Creating app state for standalone MCP server")
    
    # Initialize database-backed OAuth
    from auth.db_init import create_database_oauth_provider
    oauth = create_database_oauth_provider(
        secret_key=config.oauth.jwt_secret_key,
        access_token_expire_minutes=config.oauth.access_token_expire_minutes,
        refresh_token_expire_days=config.oauth.refresh_token_expire_days,
    )
    
    # Initialize security
    audit_logger = AuditLogger(
        log_path=config.security.audit_log_path,
        enabled=config.security.audit_enabled,
        sensitive_fields=config.security.audit_sensitive_fields,
    )
    security = SecurityContext(
        rate_limiter=RateLimiter(
            requests_per_minute=config.security.rate_limit_requests_per_minute,
            requests_per_hour=config.security.rate_limit_requests_per_hour,
        ),
        validator=InputValidator(
            max_string_length=config.security.max_string_length,
            max_request_size=config.security.max_request_size_bytes,
            sanitize_html=config.security.sanitize_html,
        ),
        audit_logger=audit_logger,
        ip_restrictions=IPRestrictions(
            whitelist=config.security.ip_whitelist,
            blacklist=config.security.ip_blacklist,
        ),
    )
    
    # Initialize backend manager
    backends = BackendManager(
        health_check_interval=config.backend.health_check_interval_seconds,
        unhealthy_threshold=config.backend.unhealthy_threshold,
    )
    
    # Register backends from definitions (synchronous)
    for backend_id, backend_def in BACKEND_DEFINITIONS.items():
        if backend_def["type"] == "mcp":
            backend_type = BackendType.MCP_STDIO
        elif backend_def.get("api_type") == "graphql":
            backend_type = BackendType.API_GRAPHQL
        else:
            backend_type = BackendType.API_REST

        # Only include env var if it has a non-empty value
        _env_val = os.getenv(backend_def["env_key"]) if backend_def.get("env_key") else None
        _env = {backend_def["env_key"]: _env_val} if _env_val else {}

        definition = BackendDefinition(
            id=backend_id,
            name=backend_def["name"],
            description=backend_def["description"],
            backend_type=backend_type,
            enabled=True,
            requires_auth=backend_def.get("requires_auth", False),
            env_key=backend_def.get("env_key"),
            connector=backend_def.get("connector"),
            tools=backend_def.get("tools", []),
            command=backend_def.get("command"),
            args=backend_def.get("args", []),
            env=_env,
            url=backend_def.get("url"),
            base_url=backend_def.get("base_url"),
            auth_type=backend_def.get("auth_type"),
        )
        backends.register_backend(definition)
    
    # NOTE: backends.start() is async, skipping for sync mode
    # In production, would need to run this in event loop
    
    # Initialize connectors (sync init)
    from connectors import ConnectorRegistry, get_registry
    import asyncio
    
    async def init_connectors():
        from connectors import initialize_connectors
        return await initialize_connectors()
    
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # If loop is running, we can't run async here
            connectors = get_registry()
        else:
            connectors = loop.run_until_complete(init_connectors())
    except RuntimeError:
        # No event loop, create one
        connectors = asyncio.run(init_connectors())
    
    # Initialize connector OAuth provider
    from auth.oauth_providers import create_oauth_provider as create_connector_oauth_provider
    connector_oauth = create_connector_oauth_provider(config)
    
    # Initialize database-backed token store
    from auth.db_init import create_database_token_store
    from auth.token_store import set_token_store
    token_store = create_database_token_store()
    set_token_store(token_store)
    
    # Store state
    state = AppState(
        config=config,
        oauth=oauth,
        connector_oauth=connector_oauth,
        security=security,
        backends=backends,
        connectors=connectors,
    )
    
    logger.info("App state created successfully")
    return state


# -----------------------------------------------------------------------------
# FastAPI Lifespan
# -----------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifecycle."""
    global state
    
    # Startup
    config = get_config()
    
    # Security: validate JWT secret is not the default
    default_secret_length = len(secrets.token_urlsafe(32))
    if len(config.oauth.jwt_secret_key) == default_secret_length:
        if not os.getenv("RELAY_ALLOW_DEFAULT_SECRET"):
            raise RuntimeError(
                "SECURITY: OAUTH_JWT_SECRET_KEY is using the default generated value. "
                "Set a strong secret via: export OAUTH_JWT_SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))') "
                "Or set RELAY_ALLOW_DEFAULT_SECRET=1 to bypass (NOT FOR PRODUCTION)."
            )
    
    # Initialize database
    from auth import database as db
    db.init_db()
    
    # Initialize database-backed OAuth
    from auth.db_init import create_database_oauth_provider
    oauth = create_database_oauth_provider(
        secret_key=config.oauth.jwt_secret_key,
        access_token_expire_minutes=config.oauth.access_token_expire_minutes,
        refresh_token_expire_days=config.oauth.refresh_token_expire_days,
    )
    
    # Initialize security
    audit_logger = AuditLogger(
        log_path=config.security.audit_log_path,
        enabled=config.security.audit_enabled,
        sensitive_fields=config.security.audit_sensitive_fields,
    )
    security = SecurityContext(
        rate_limiter=RateLimiter(
            requests_per_minute=config.security.rate_limit_requests_per_minute,
            requests_per_hour=config.security.rate_limit_requests_per_hour,
        ),
        validator=InputValidator(
            max_string_length=config.security.max_string_length,
            max_request_size=config.security.max_request_size_bytes,
            sanitize_html=config.security.sanitize_html,
        ),
        audit_logger=audit_logger,
        ip_restrictions=IPRestrictions(
            whitelist=config.security.ip_whitelist,
            blacklist=config.security.ip_blacklist,
        ),
    )
    
    # Initialize backend manager
    backends = BackendManager(
        health_check_interval=config.backend.health_check_interval_seconds,
        unhealthy_threshold=config.backend.unhealthy_threshold,
    )
    
    # Register backends from definitions
    for backend_id, backend_def in BACKEND_DEFINITIONS.items():
        if backend_def["type"] == "mcp":
            backend_type = BackendType.MCP_STDIO
        elif backend_def.get("api_type") == "graphql":
            backend_type = BackendType.API_GRAPHQL
        else:
            backend_type = BackendType.API_REST

        _env_val = os.getenv(backend_def["env_key"]) if backend_def.get("env_key") else None
        _env = {backend_def["env_key"]: _env_val} if _env_val else {}

        definition = BackendDefinition(
            id=backend_id,
            name=backend_def["name"],
            description=backend_def["description"],
            backend_type=backend_type,
            enabled=True,
            requires_auth=backend_def.get("requires_auth", False),
            env_key=backend_def.get("env_key"),
            connector=backend_def.get("connector"),
            tools=backend_def.get("tools", []),
            command=backend_def.get("command"),
            args=backend_def.get("args", []),
            env=_env,
            url=backend_def.get("url"),
            base_url=backend_def.get("base_url"),
            auth_type=backend_def.get("auth_type"),
        )
        backends.register_backend(definition)
    
    await backends.start()
    
    # Initialize connectors from environment
    connectors = await initialize_connectors()
    
    # Initialize connector OAuth provider
    connector_oauth = create_connector_oauth_provider(config)
    
    # Initialize database-backed token store for third-party tokens
    from auth.db_init import create_database_token_store
    token_store = create_database_token_store()
    set_token_store(token_store)
    
    # Store state
    state = AppState(
        config=config,
        oauth=oauth,
        connector_oauth=connector_oauth,
        security=security,
        backends=backends,
        connectors=connectors,
    )
    
    # Mount per-connector MCP servers on /mcp/{connector}
    # Note: This is for shared/default tokens. For per-user MCP, use /user-mcp/{api_key}/{connector}/mcp
    connector_session_managers = []
    for conn_name in ConnectorRegistry.CONNECTOR_TYPES:
        connector_mcp = create_connector_mcp_server(conn_name, app_state=state)
        if connector_mcp is not None:
            connector_asgi = connector_mcp.streamable_http_app()
            connector_session_managers.append(connector_mcp._session_manager)
            mount_path = f"/mcp/{conn_name}"
            app.mount(mount_path, connector_asgi)
            logger.info(f"Mounted connector MCP server: {mount_path}")
    
    # Start all connector session managers
    from contextlib import AsyncExitStack
    async with AsyncExitStack() as stack:
        for sm in connector_session_managers:
            await stack.enter_async_context(sm.run())
        logger.info(f"Relay started on {config.server.host}:{config.server.port}")
        yield
    
    # Shutdown
    await backends.stop()
    await connectors.close_all()
    logger.info("Relay stopped")


# -----------------------------------------------------------------------------
# FastAPI App
# -----------------------------------------------------------------------------

app = FastAPI(
    title="Relay",
    description="OAuth-authenticated MCP proxy for third-party services",
    version="0.1.0",
    lifespan=lifespan,
)

# Static files
import os
_static_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static")
if os.path.isdir(_static_dir):
    app.mount("/static", StaticFiles(directory=_static_dir), name="static")

# Jinja2 templates
_template_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")
if os.path.isdir(_template_dir):
    templates = Environment(
        loader=FileSystemLoader(_template_dir),
        autoescape=True,
    )
else:
    templates = None


def render_template(name: str, **context) -> HTMLResponse:
    """Render a Jinja2 template."""
    if templates is None:
        return HTMLResponse(content="<h1>Templates not available</h1>", status_code=500)
    template = templates.get_template(name)
    return HTMLResponse(content=template.render(**context))


# CORS middleware.
# allow_credentials=True is incompatible with allow_origins=["*"] (CORS spec).
# In development we allow all origins but disable credentials; in production
# use an explicit origin list from config so credentials can be enabled.
_startup_config = get_config()
_cors_origins = _startup_config.server.cors_origins
_cors_credentials = "*" not in _cors_origins

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=_cors_credentials,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# Request ID tracing — registered after CORS so it wraps the full stack
app.add_middleware(RequestIDMiddleware)

# HSTS for production security
from security.middleware import HSTSMiddleware
app.add_middleware(HSTSMiddleware)


# Normalize all error responses to {"error": "..."} so clients never see
# FastAPI's default {"detail": "..."} shape mixed with our own shape.
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content={"error": exc.detail})


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception(f"Unhandled exception on {request.method} {request.url.path}")
    return JSONResponse(status_code=500, content={"error": "Internal server error"})


# -----------------------------------------------------------------------------
# Authentication Dependencies
# -----------------------------------------------------------------------------

async def get_current_user(
    request: Request,
    authorization: Optional[str] = None,
) -> Dict[str, Any]:
    """
    FastAPI dependency to extract and validate authenticated user.
    
    Raises 401 if not authenticated.
    """
    if not authorization:
        authorization = request.headers.get("Authorization")
    
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid Authorization header format")
    
    token = authorization[7:]  # Remove "Bearer " prefix
    
    user_info = state.oauth.validate_access_token(token)
    if not user_info:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    return user_info


async def get_client_ip(request: Request) -> str:
    """
    Extract client IP from request.

    X-Forwarded-For is only trusted when the gateway is explicitly configured
    to run behind a reverse proxy (TRUSTED_PROXY env var set to "1").
    When trusted, we take the *last* IP added by a trusted upstream proxy
    (rightmost entry), not the leftmost which is client-controlled.
    Without proxy trust, fall back to the direct TCP peer address.
    """
    if os.getenv("TRUSTED_PROXY") == "1":
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            # Rightmost entry is added by our trusted proxy
            parts = [p.strip() for p in forwarded.split(",") if p.strip()]
            if parts:
                return parts[-1]
    return request.client.host if request.client else "unknown"


# -----------------------------------------------------------------------------
# OAuth Endpoints
# -----------------------------------------------------------------------------

class ClientRegistrationRequest(BaseModel):
    """OAuth client registration request."""
    client_name: str
    redirect_uris: List[str]
    is_confidential: bool = True


class AuthorizeRequest(BaseModel):
    """OAuth authorization request."""
    client_id: str
    redirect_uri: str
    code_challenge: str
    code_challenge_method: str = "S256"
    scope: str = "mcp:tools"
    state: Optional[str] = None


class TokenRequest(BaseModel):
    """OAuth token request."""
    grant_type: str
    code: Optional[str] = None
    code_verifier: Optional[str] = None
    client_id: str
    redirect_uri: Optional[str] = None
    refresh_token: Optional[str] = None


@app.post("/oauth/register", tags=["OAuth"])
async def register_client(req: ClientRegistrationRequest):
    """Register a new OAuth client."""
    app_state = _get_state()
    client = app_state.oauth.register_client(
        client_name=req.client_name,
        redirect_uris=req.redirect_uris,
        is_confidential=req.is_confidential,
    )
    return {
        "client_id": client.client_id,
        "client_name": client.client_name,
        "redirect_uris": client.redirect_uris,
    }


@app.get("/oauth/authorize", tags=["OAuth"])
async def authorize_page(
    client_id: str,
    redirect_uri: str,
    code_challenge: str,
    code_challenge_method: str = "S256",
    scope: str = "mcp:tools",
    oauth_state: Optional[str] = None,  # renamed — avoids shadowing the global AppState
):
    """
    OAuth authorization endpoint - shows consent page.

    For POC, auto-approves. In production, show UI for user consent.
    """
    app_state = _get_state()

    # Validate client and redirect URI
    client = app_state.oauth.get_client(client_id)
    if not client:
        raise HTTPException(status_code=400, detail="Invalid client_id")

    if not app_state.oauth.validate_redirect_uri(client_id, redirect_uri):
        raise HTTPException(status_code=400, detail="Invalid redirect_uri")

    # For POC: auto-approve and redirect
    # In production: render consent page, get user approval
    code = app_state.oauth.create_authorization_code(
        client_id=client_id,
        redirect_uri=redirect_uri,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        scope=scope,
    )

    # Log the authorization
    if app_state.security.audit:
        app_state.security.audit.log(
            event_type="oauth_authorize",
            client_id=client_id,
            user_id="demo_user",
            ip_address="unknown",
            resource="oauth",
            action="authorize",
            success=True,
            details={"scope": scope},
        )

    # For POC: return JSON with redirect info
    # In production: return HTMLResponse with consent page or redirect
    redirect_url = f"{redirect_uri}?code={code}"
    if oauth_state:
        redirect_url += f"&state={oauth_state}"

    return {
        "code": code,
        "redirect_uri": redirect_uri,
        "state": oauth_state,
        "message": "Authorization granted (auto-approved for POC)",
    }


@app.post("/oauth/token", tags=["OAuth"])
async def token_endpoint(req: TokenRequest):
    """OAuth token endpoint - exchange code for tokens."""
    app_state = _get_state()
    if req.grant_type == "authorization_code":
        if not req.code or not req.code_verifier:
            raise HTTPException(status_code=400, detail="Missing code or code_verifier")

        token_pair = app_state.oauth.exchange_code_for_token(
            code=req.code,
            code_verifier=req.code_verifier,
            client_id=req.client_id,
            redirect_uri=req.redirect_uri,
        )
        
        if not token_pair:
            raise HTTPException(status_code=400, detail="Invalid authorization code")
        
        return {
            "access_token": token_pair.access_token,
            "refresh_token": token_pair.refresh_token,
            "token_type": token_pair.token_type,
            "expires_in": token_pair.expires_in,
            "scope": token_pair.scope,
        }
    
    elif req.grant_type == "refresh_token":
        if not req.refresh_token:
            raise HTTPException(status_code=400, detail="Missing refresh_token")

        token_pair = app_state.oauth.refresh_access_token(
            refresh_token=req.refresh_token,
            client_id=req.client_id,
        )
        
        if not token_pair:
            raise HTTPException(status_code=400, detail="Invalid refresh token")
        
        return {
            "access_token": token_pair.access_token,
            "refresh_token": token_pair.refresh_token,
            "token_type": token_pair.token_type,
            "expires_in": token_pair.expires_in,
            "scope": token_pair.scope,
        }
    
    else:
        raise HTTPException(status_code=400, detail="Unsupported grant_type")


@app.post("/oauth/revoke", tags=["OAuth"])
async def revoke_token(request: Request):
    """Revoke an access or refresh token."""
    app_state = _get_state()
    body = await request.json()
    token = body.get("token")

    if not token:
        raise HTTPException(status_code=400, detail="Missing token")

    success = app_state.oauth.revoke_token(token)
    return {"revoked": success}


# -----------------------------------------------------------------------------
# User Authentication Endpoints
# -----------------------------------------------------------------------------

class UserRegisterRequest(BaseModel):
    """User registration request."""
    username: str
    password: str
    email: Optional[str] = None


class UserLoginRequest(BaseModel):
    """User login request."""
    username: str
    password: str


class UserUpdateRequest(BaseModel):
    """User profile update request."""
    username: Optional[str] = None
    email: Optional[str] = None
    current_password: Optional[str] = None
    new_password: Optional[str] = None


def hash_password(password: str) -> str:
    """Hash a password using PBKDF2-HMAC-SHA256 (stdlib, no external deps)."""
    import hashlib
    import base64
    import os
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
    return base64.b64encode(salt + dk).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its PBKDF2-HMAC-SHA256 hash."""
    import hashlib
    import base64
    raw = base64.b64decode(hashed_password.encode("utf-8"))
    salt = raw[:16]
    stored_dk = raw[16:]
    dk = hashlib.pbkdf2_hmac("sha256", plain_password.encode("utf-8"), salt, 100_000)
    return dk == stored_dk


def create_session_token(user_id: str) -> str:
    """Create a session JWT token (24h expiry)."""
    jwt_manager = state.oauth.jwt
    from datetime import timedelta
    return jwt_manager.create_access_token(
        user_id=user_id,
        client_id="session",
        scope="session",
        expires_delta=timedelta(hours=24),
    )


def get_user_from_session(request: Request) -> Optional[Dict[str, Any]]:
    """Extract user from session cookie."""
    session_token = request.cookies.get("session")
    if not session_token:
        return None
    
    payload = state.oauth.jwt.decode_token(session_token)
    if not payload or payload.scope != "session":
        return None
    
    from auth import database as db
    user = db.get_user_by_id(payload.sub)
    if not user or not user.get("is_active"):
        return None
    
    # Get or create API key for the user
    from auth.database import list_api_keys, create_api_key
    api_keys = list_api_keys(user["id"])
    if not api_keys:
        api_key = create_api_key(user["id"], "Default")
    else:
        api_key = api_keys[0]["key"]
    
    user["api_key"] = api_key
    return user


async def get_current_session_user(request: Request) -> Dict[str, Any]:
    """FastAPI dependency: require authenticated session."""
    user = get_user_from_session(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


@app.post("/auth/register", tags=["Auth"])
async def register_user(req: UserRegisterRequest):
    """Register a new user account."""
    if len(req.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    
    if not req.username or len(req.username) < 3:
        raise HTTPException(status_code=400, detail="Username must be at least 3 characters")
    
    import re
    if not re.match(r'^[a-zA-Z0-9_]+$', req.username):
        raise HTTPException(status_code=400, detail="Username can only contain letters, numbers, and underscores")
    
    import secrets
    user_id = f"usr_{secrets.token_urlsafe(12)}"
    hashed_pw = hash_password(req.password)
    
    from auth import database as db
    result = db.create_user(
        user_id=user_id,
        username=req.username,
        hashed_password=hashed_pw,
        email=req.email,
    )
    
    if not result:
        raise HTTPException(status_code=409, detail="Username or email already exists")
    
    return {
        "user_id": user_id,
        "username": req.username,
        "email": req.email,
    }


@app.post("/auth/login", tags=["Auth"])
async def login_user(req: UserLoginRequest, response: Response):
    """Login and set session cookie."""
    from auth import database as db
    from fastapi.responses import JSONResponse
    
    user_data = db.get_user_by_username(req.username)
    if not user_data:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if not user_data.get("is_active"):
        raise HTTPException(status_code=403, detail="Account is deactivated")
    
    if not verify_password(req.password, user_data["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    session_token = create_session_token(user_data["id"])
    
    # Get or create API key for user
    from auth.database import list_api_keys, create_api_key
    api_keys = list_api_keys(user_data["id"])
    if not api_keys:
        api_key = create_api_key(user_data["id"], "Default")
    else:
        api_key = api_keys[0]["key"]
    
    resp = JSONResponse(content={
        "user_id": user_data["id"],
        "username": user_data["username"],
        "api_key": api_key,
    })
    resp.set_cookie(
        key="session",
        value=session_token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=86400,
        path="/",
    )
    return resp


@app.post("/auth/logout", tags=["Auth"])
async def logout_user(response: Response):
    """Logout and clear session cookie, then redirect to login."""
    resp = RedirectResponse(url="/auth/login", status_code=302)
    resp.delete_cookie(key="session", path="/")
    return resp


@app.get("/auth/me", tags=["Auth"])
async def get_me(user: Dict = Depends(get_current_session_user)):
    """Get current user info."""
    return {
        "id": user["id"],
        "username": user["username"],
        "email": user.get("email"),
    }


@app.put("/auth/me", tags=["Auth"])
async def update_me(
    req: UserUpdateRequest,
    user: Dict = Depends(get_current_session_user),
):
    """Update current user profile."""
    from auth import database as db
    
    user_id = user["id"]
    new_hashed_password = None
    
    if req.new_password:
        if not req.current_password:
            raise HTTPException(status_code=400, detail="Current password required to change password")
        
        user_data = db.get_user_by_id(user_id)
        if not user_data or not verify_password(req.current_password, user_data.get("hashed_password", "")):
            raise HTTPException(status_code=401, detail="Current password is incorrect")
        
        if len(req.new_password) < 8:
            raise HTTPException(status_code=400, detail="New password must be at least 8 characters")
        
        new_hashed_password = hash_password(req.new_password)
    
    db.update_user(
        user_id=user_id,
        username=req.username,
        email=req.email,
        hashed_password=new_hashed_password,
    )
    
    updated = db.get_user_by_id(user_id)
    return {
        "id": updated["id"],
        "username": updated["username"],
        "email": updated.get("email"),
    }


# -----------------------------------------------------------------------------
# Web UI Routes
# -----------------------------------------------------------------------------

@app.get("/auth/login", tags=["Web UI"])
async def login_page(request: Request):
    """Login page."""
    user = get_user_from_session(request)
    if user:
        return RedirectResponse(url="/app")
    return render_template("login.html")


@app.get("/auth/register", tags=["Web UI"])
async def register_page(request: Request):
    """Registration page."""
    user = get_user_from_session(request)
    if user:
        return RedirectResponse(url="/app")
    return render_template("register.html")


@app.get("/app", tags=["Web UI"])
async def dashboard_page(request: Request):
    """Dashboard - shows home page for logged-in users, redirects to login otherwise."""
    user = get_user_from_session(request)
    if not user:
        return RedirectResponse(url="/auth/login")
    
    app_state = _get_state()
    
    connectors_data = []
    connected_count = 0
    for conn in await app_state.connectors.list_connectors_async():
        name = conn.get("name", "")
        try:
            token = await get_token_store().get_token(user["id"], name)
            is_connected = token is not None
        except Exception:
            is_connected = False
        if is_connected:
            connected_count += 1
        connectors_data.append({
            "name": name,
            "display_name": conn.get("display_name", name.title()),
            "tools_count": len(conn.get("tools", [])),
            "connected": is_connected,
        })
    
    backends = app_state.backends.list_backends()
    
    return render_template(
        "dashboard.html",
        user=user,
        connected_count=connected_count,
        total_tools=sum(c["tools_count"] for c in connectors_data),
        api_keys_count=0,
        backends_count=len([b for b in backends if b.get("status") == "healthy"]),
        connectors=connectors_data,
    )


@app.get("/connectors", tags=["Web UI"])
async def connectors_page(request: Request):
    """Connectors management page."""
    user = get_user_from_session(request)
    if not user:
        return RedirectResponse(url="/auth/login")
    
    app_state = _get_state()
    
    connectors_data = []
    for conn in await app_state.connectors.list_connectors_async():
        name = conn.get("name", "")
        try:
            token = await get_token_store().get_token(user["id"], name)
            is_connected = token is not None
        except Exception:
            is_connected = False
        connectors_data.append({
            "name": name,
            "display_name": conn.get("display_name", name.title()),
            "description": conn.get("description", ""),
            "tools_count": len(conn.get("tools", [])),
            "connected": is_connected,
            "connected_as": None,
        })
    
    return render_template(
        "connectors.html",
        user=user,
        connectors=connectors_data,
    )


@app.post("/connectors/{connector_name}/disconnect", tags=["Web UI"])
async def disconnect_connector(connector_name: str, request: Request):
    """Disconnect a connector for the current user."""
    user = get_user_from_session(request)
    if not user:
        return RedirectResponse(url="/auth/login")
    
    await get_token_store().delete_token(user["id"], connector_name)
    return RedirectResponse(url=f"/connectors/{connector_name}", status_code=303)


@app.get("/connectors/{connector_name}", tags=["Web UI"])
async def connector_detail_page(connector_name: str, request: Request):
    """Connector detail page showing prompts, resources, and tools."""
    user = get_user_from_session(request)
    if not user:
        return RedirectResponse(url="/auth/login")
    
    app_state = _get_state()
    
    # Find the connector
    conn = None
    for c in app_state.connectors.list_connectors():
        if c.get("name") == connector_name:
            conn = c
            break
    
    if not conn:
        raise HTTPException(status_code=404, detail="Connector not found")
    
    # Check if connected for this user
    try:
        token = await get_token_store().get_token(user["id"], connector_name)
        is_connected = token is not None
    except Exception:
        is_connected = False
    
    # Get detailed connector info
    connector_obj = app_state.connectors.get_connector(connector_name)
    tools = []
    resources = []
    prompts = []
    
    if connector_obj:
        # Get tools (try async first, then sync)
        try:
            if hasattr(connector_obj, "get_tools_async"):
                tools = await connector_obj.get_tools_async()
            else:
                tools = connector_obj.get_tools()
        except Exception:
            tools = connector_obj.get_tools()
        
        tools_data = []
        for tool in tools:
            tools_data.append({
                "name": tool.name,
                "description": tool.description,
                "parameters": tool.parameters,
            })
        tools = tools_data
        
        # Get resources if available
        if hasattr(connector_obj, "get_resources"):
            for resource in connector_obj.get_resources():
                resources.append({
                    "uri": resource.uri,
                    "name": resource.name,
                    "description": resource.description,
                    "mime_type": resource.mime_type,
                })
        
        # Get prompts if available
        if hasattr(connector_obj, "get_prompts"):
            for prompt in connector_obj.get_prompts():
                prompts.append({
                    "name": prompt.name,
                    "description": prompt.description,
                    "arguments": prompt.arguments,
                })
    
    return render_template(
        "connector_detail.html",
        user=user,
        connector={
            "name": connector_name,
            "display_name": conn.get("display_name", connector_name.title()),
            "description": conn.get("description", ""),
            "tools": tools,
            "resources": resources,
            "prompts": prompts,
            "connected": is_connected,
            "healthy": conn.get("healthy", False),
            "total_calls": conn.get("total_calls", 0),
            "total_errors": conn.get("total_errors", 0),
        },
        api_key=user.get("api_key"),  # Pass user's primary API key
    )


@app.get("/api-keys", tags=["Web UI"])
async def api_keys_page(request: Request):
    """API keys management page."""
    user = get_user_from_session(request)
    if not user:
        return RedirectResponse(url="/auth/login")
    
    # Get user's API keys from database
    from auth.database import list_api_keys
    api_keys = list_api_keys(user["id"])
    primary_api_key = api_keys[0]["key"] if api_keys else None
    
    return render_template(
        "api_keys.html",
        user=user,
        api_keys=api_keys,
        primary_api_key=primary_api_key,
    )


@app.post("/api-keys/create", tags=["Web UI"])
async def create_api_key_action(request: Request):
    """Create a new API key for the user."""
    user = get_user_from_session(request)
    if not user:
        return RedirectResponse(url="/auth/login")
    
    # Parse form data
    form = await request.form()
    key_name = form.get("name", "My API Key")
    
    # Create API key
    from auth.database import create_api_key
    new_key = create_api_key(user["id"], key_name)
    
    # Store in session temporarily for display
    request.session["new_api_key"] = new_key
    
    return RedirectResponse(url="/api-keys?show_key=1")


@app.post("/api-keys/{key}/revoke", tags=["Web UI"])
async def revoke_api_key(key: str, request: Request):
    """Revoke an API key."""
    user = get_user_from_session(request)
    if not user:
        return RedirectResponse(url="/auth/login")
    
    from auth.database import delete_api_key
    delete_api_key(user["id"], key)
    
    return RedirectResponse(url="/api-keys")


@app.get("/api-keys/{client_id}", tags=["Web UI"])
async def api_key_detail_page(client_id: str, request: Request):
    """API key detail page."""
    user = get_user_from_session(request)
    if not user:
        return RedirectResponse(url="/auth/login")
    
    app_state = _get_state()
    client = app_state.oauth.get_client(client_id)
    
    if not client:
        raise HTTPException(status_code=404, detail="API key not found")
    
    return render_template(
        "api_key_detail.html",
        user=user,
        api_key={
            "client_id": client.client_id,
            "client_name": client.client_name,
            "redirect_uris": client.redirect_uris,
            "is_confidential": client.is_confidential,
        },
    )


@app.get("/settings", tags=["Web UI"])
async def settings_page(request: Request):
    """User settings page."""
    user = get_user_from_session(request)
    if not user:
        return RedirectResponse(url="/auth/login")
    
    return render_template(
        "settings.html",
        user=user,
    )


@app.get("/", tags=["Web UI"])
async def root_redirect(request: Request):
    """Root path redirects to dashboard if logged in, otherwise to login."""
    user = get_user_from_session(request)
    if user:
        return RedirectResponse(url="/app")
    return RedirectResponse(url="/auth/login"    )


@app.get("/backends", tags=["Web UI"])
async def backends_page(request: Request):
    """Backends management page."""
    user = get_user_from_session(request)
    if not user:
        return RedirectResponse(url="/auth/login")
    
    app_state = _get_state()
    backends = app_state.backends.list_backends()
    
    return render_template(
        "backends.html",
        user=user,
        backends=backends,
    )


@app.get("/backends/{backend_id}", tags=["Web UI"])
async def backend_detail_page(backend_id: str, request: Request):
    """Backend detail page."""
    user = get_user_from_session(request)
    if not user:
        return RedirectResponse(url="/auth/login")
    
    app_state = _get_state()
    backends = app_state.backends.list_backends()
    
    backend = None
    for b in backends:
        if b["id"] == backend_id:
            backend = b
            break
    
    if not backend:
        raise HTTPException(status_code=404, detail="Backend not found")
    
    return render_template(
        "backend_detail.html",
        user=user,
        backend=backend,
    )


@app.get("/api/info", tags=["Info"])
async def api_info():
    """Gateway info endpoint (API only)."""
    app_state = _get_state()
    return {
        "name": app_state.config.server.server_name,
        "version": app_state.config.server.server_version,
        "status": "running",
        "started_at": app_state.started_at.isoformat(),
        "endpoints": {
            "oauth": {
                "register": "/oauth/register",
                "authorize": "/oauth/authorize",
                "token": "/oauth/token",
                "revoke": "/oauth/revoke",
            },
            "api_keys": {
                "create": "/v1/api-keys",
                "usage": "Authorization: Bearer <api_key> or ApiKey: <api_key>",
            },
            "v1_rest_api": {
                "tools": "/v1/tools (public discovery)",
                "tool_schema": "/v1/tools/{tool_name} (public)",
                "call": "/v1/call (requires auth)",
                "batch": "/v1/batch (requires auth)",
                "connectors": "/v1/connectors (public discovery)",
            },
            "mcp_compatible": {
                "tools": "/mcp/tools (requires auth)",
                "call": "/mcp/call (requires auth)",
                "backends": "/mcp/backends (requires auth)",
                "connectors": "/mcp/connectors (requires auth)",
            },
            "health": "/health",
        },
        "documentation": {
            "openapi": "/docs",
            "redoc": "/redoc",
        },
    }


@app.get("/health", tags=["Info"])
async def health():
    """Health check endpoint."""
    app_state = _get_state()
    backends_info = app_state.backends.list_backends()
    backends_healthy = sum(1 for b in backends_info if b["status"] == "healthy")
    backends_total = len(backends_info)
    circuit_open = sum(
        1 for b in backends_info
        if b.get("circuit_breaker", {}).get("state") == "open"
    )

    return {
        "status": "healthy",
        "uptime_seconds": (datetime.now(timezone.utc) - app_state.started_at).total_seconds(),
        "backends": {
            "healthy": backends_healthy,
            "total": backends_total,
            "circuit_open": circuit_open,
        },
    }


@app.get("/mcp/backends", tags=["MCP Compatible"])
async def list_backends(user: Dict = Depends(get_current_user)):
    """List all available backends and their status."""
    return state.backends.list_backends()


@app.post("/mcp/backends/{backend_id}/connect", tags=["MCP Compatible"])
async def connect_backend(
    backend_id: str, 
    user: Dict = Depends(get_current_user),
    ip: str = Depends(get_client_ip),
):
    """Connect to a specific backend."""
    # Security check
    allowed, info = state.security.check_request(
        client_id=user["client_id"],
        ip_address=ip,
        user_id=user["user_id"],
    )
    if not allowed:
        raise HTTPException(status_code=429, detail=info)
    
    success, error = await state.backends.connect_backend(backend_id)
    
    if not success:
        raise HTTPException(status_code=400, detail=error)
    
    return {"connected": True, "backend_id": backend_id}


@app.get("/mcp/tools", tags=["MCP Compatible"])
async def list_tools(user: Dict = Depends(get_current_user)):
    """List all available tools across backends and connectors (authenticated)."""
    backend_tools = state.backends.list_tools()
    connector_tools = state.connectors.get_all_tools()
    
    return {
        "backend_tools": backend_tools,
        "connector_tools": connector_tools,
        "total": len(backend_tools) + len(connector_tools),
    }


# -----------------------------------------------------------------------------
# Public Discovery Endpoints (No Auth Required)
# -----------------------------------------------------------------------------

@app.get("/v1/tools", tags=["Discovery"])
async def discover_tools():
    """
    Public tool discovery endpoint - no authentication required.
    
    Returns tools in OpenAI-compatible format for easy SDK integration.
    Used by CLIs and SDKs to discover available tools before authentication.
    """
    app_state = _get_state()
    backend_tools = app_state.backends.list_tools()
    connector_tools = app_state.connectors.get_all_tools()
    
    # Format in OpenAI-compatible tool format
    all_tools = []
    
    for tool in backend_tools + connector_tools:
        all_tools.append({
            "type": "function",
            "function": {
                "name": tool.get("name", ""),
                "description": tool.get("description", ""),
                "parameters": tool.get("parameters", {}),
            },
            "x-connector": tool.get("connector"),
            "x-requires-auth": tool.get("requires_auth", False),
        })
    
    return {
        "object": "list",
        "data": all_tools,
        "total": len(all_tools),
    }


@app.get("/v1/tools/{tool_name}", tags=["Discovery"])
async def get_tool_schema(tool_name: str):
    """
    Get JSON schema for a specific tool - no authentication required.
    
    Returns MCP-compatible tool schema for SDK code generation.
    """
    # Check connectors first
    connector_schema = state.connectors.get_tool_schema(tool_name)
    if connector_schema:
        return {
            "name": tool_name,
            "schema": connector_schema,
        }
    
    # Check backends
    for tool in state.backends.list_tools():
        if tool.get("name") == tool_name:
            return {
                "name": tool_name,
                "schema": {
                    "name": tool_name,
                    "description": tool.get("description", ""),
                    "inputSchema": {
                        "type": "object",
                        **tool.get("parameters", {}),
                    },
                },
            }
    
    raise HTTPException(status_code=404, detail=f"Tool not found: {tool_name}")


@app.get("/v1/connectors", tags=["Discovery"])
async def discover_connectors():
    """
    Public connector discovery endpoint - no authentication required.
    
    Lists all available third-party connectors and their status.
    """
    return {
        "connectors": [
            {
                "name": c.get("name"),
                "display_name": c.get("display_name"),
                "description": c.get("description"),
                "tools_count": len(c.get("tools", [])),
                "healthy": c.get("healthy"),
            }
            for c in state.connectors.list_connectors()
        ]
    }


# -----------------------------------------------------------------------------
# API Key Authentication (Alternative to OAuth)
# -----------------------------------------------------------------------------

async def get_current_user_api_key(
    request: Request,
    authorization: Optional[str] = None,
) -> Dict[str, Any]:
    """
    FastAPI dependency for API key authentication (simpler than OAuth).
    
    Supports:
    - Bearer token (OAuth access token)
    - ApiKey header (simple API key)
    
    For API keys, the key IS the access token (created via OAuth register).
    """
    if not authorization:
        authorization = request.headers.get("Authorization") or request.headers.get("ApiKey")
    
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization or ApiKey header")
    
    # Handle ApiKey header
    if authorization.startswith("sk-"):
        token = authorization
    # Handle Bearer token
    elif authorization.startswith("Bearer "):
        token = authorization[7:]  # Remove "Bearer " prefix
    else:
        # Treat as raw API key
        token = authorization
    
    # Validate token
    user_info = state.oauth.validate_access_token(token)
    if not user_info:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    return user_info


@app.post("/v1/api-keys", tags=["API Keys"])
async def create_api_key(
    req: ClientRegistrationRequest,
):
    """
    Create a simple API key for programmatic access.
    
    This is a simplified flow for CLIs and SDKs that don't want OAuth:
    1. Register with a name and callback URL
    2. Get an API key (sk-...) immediately
    3. Use the API key in Authorization: Bearer sk-... or ApiKey: sk-...
    """
    # Register as OAuth client
    client = state.oauth.register_client(
        client_name=req.client_name,
        redirect_uris=req.redirect_uris or ["urn:ietf:wg:oauth:2.0:oob"],
        is_confidential=False,  # Public client for API key flow
    )
    
    # Create an access token directly (bypass OAuth flow)
    # The API key IS the access token
    token_pair = state.oauth._create_token_pair(
        client_id=client.client_id,
        user_id=f"api-key-{client.client_name}",
        scope="mcp:tools",
    )
    
    return {
        "api_key": token_pair.access_token,
        "client_id": client.client_id,
        "client_name": client.client_name,
        "expires_in": token_pair.expires_in,
        "usage": {
            "header": "Authorization: Bearer <api_key>",
            "alt_header": "ApiKey: <api_key>",
        },
    }


# -----------------------------------------------------------------------------
# v1 REST API Endpoints (OpenAI-Compatible)
# -----------------------------------------------------------------------------

class V1ToolCallRequest(BaseModel):
    """OpenAI-compatible tool call request."""
    tool_name: str
    arguments: Dict[str, Any] = {}
    timeout: int = 120


@app.post("/v1/call", tags=["Tool Execution"])
async def v1_call_tool(
    req: V1ToolCallRequest,
    user: Dict = Depends(get_current_user_api_key),
    ip: str = Depends(get_client_ip),
):
    """
    Execute a tool call - OpenAI-compatible endpoint.
    
    Supports both OAuth Bearer tokens and simple API keys.
    
    Example:
        curl -X POST https://gateway/v1/call \
          -H "Authorization: Bearer sk-xxx" \
          -H "Content-Type: application/json" \
          -d '{"tool_name": "github_search_repositories", "arguments": {"query": "mcp"}}'
    """
    success, result = await _execute_tool(
        tool_name=req.tool_name,
        arguments=req.arguments,
        timeout=req.timeout,
        user=user,
        ip=ip,
    )
    
    if not success:
        return JSONResponse(
            status_code=400,
            content={"error": result},
        )
    
    return {
        "object": "tool.call",
        "tool_name": req.tool_name,
        "success": True,
        "result": result,
    }


@app.post("/v1/batch", tags=["Tool Execution"])
async def v1_batch_call(
    requests: List[V1ToolCallRequest],
    user: Dict = Depends(get_current_user_api_key),
    ip: str = Depends(get_client_ip),
):
    """
    Execute multiple tool calls in parallel and return results in order.

    Maximum 10 tools per batch.  All calls are dispatched concurrently via
    ``asyncio.gather`` so total wall-clock time is roughly equal to the
    slowest single call rather than the sum of all calls.
    """
    if len(requests) > 10:
        raise HTTPException(status_code=400, detail="Maximum 10 tools per batch")

    async def _run_one(req: V1ToolCallRequest) -> Dict[str, Any]:
        try:
            success, result = await _execute_tool(
                tool_name=req.tool_name,
                arguments=req.arguments,
                timeout=req.timeout,
                user=user,
                ip=ip,
            )
            if success:
                return {"tool_name": req.tool_name, "success": True, "result": result}
            return {"tool_name": req.tool_name, "success": False, "error": result}
        except HTTPException as exc:
            return {"tool_name": req.tool_name, "success": False, "error": exc.detail}
        except Exception as exc:
            return {"tool_name": req.tool_name, "success": False, "error": str(exc)}

    results = await asyncio.gather(*[_run_one(req) for req in requests])

    return {
        "object": "tool.batch",
        "results": list(results),
        "total": len(results),
    }


@app.api_route("/user-mcp/{api_key}/{connector_name}/mcp", methods=["GET", "POST"], tags=["MCP Compatible"])
async def per_user_mcp_endpoint(
    api_key: str,
    connector_name: str,
    request: Request,
):
    """
    Per-user MCP endpoint using API key authentication.
    
    The API key is in the URL path, identifying the user.
    Forwards to the pre-mounted MCP server at /mcp/{connector_name}.
    
    Example: /user-mcp/relay_abc123/github/mcp
    """
    from auth.database import get_api_key, update_api_key_last_used
    
    # Validate API key
    key_data = get_api_key(api_key)
    if not key_data:
        return JSONResponse(status_code=401, content={"error": "Invalid API key"})
    
    user_id = key_data["user_id"]
    
    # Update last used
    update_api_key_last_used(api_key)
    
    # Find the mounted connector MCP server
    mount_path = f"/mcp/{connector_name}"
    mounted_app = None
    
    # Routes are of type Mount for mounted apps
    from starlette.routing import Mount
    for route in app.routes:
        if isinstance(route, Mount) and route.path == mount_path:
            mounted_app = route.app
            break
    
    if mounted_app is None:
        return JSONResponse(status_code=404, content={"error": f"Connector MCP server not mounted: {connector_name}"})
    
    # Modify scope: replace /user-mcp/{api_key}/{connector}/mcp with /mcp
    scope = dict(request.scope)
    scope["path"] = "/mcp"
    
    # Add user_id header for the MCP server to use
    new_headers = [(k, v) for k, v in scope.get("headers", [])]
    new_headers.append((b"x-user-id", user_id.encode()))
    scope["headers"] = new_headers
    
    # Forward to the mounted MCP server
    await mounted_app(scope, request.receive, request._send)
    
    # Return empty response (the ASGI app has already sent the response)
    return Response(content="")


@app.post("/mcp/connectors/{connector_name}/health", tags=["MCP Compatible"])
async def check_connector_health(
    connector_name: str,
    user: Dict = Depends(get_current_user),
):
    """Check health of a specific connector."""
    connector = state.connectors.get_connector(connector_name)
    if not connector:
        raise HTTPException(status_code=404, detail=f"Connector not found: {connector_name}")
    
    healthy, message = await connector.health_check()
    return {
        "connector": connector_name,
        "healthy": healthy,
        "message": message,
    }


class ToolCallRequest(BaseModel):
    """Tool call request."""
    tool_name: str
    arguments: Dict[str, Any] = {}
    backend_id: Optional[str] = None
    timeout: int = 120


async def _execute_tool(
    tool_name: str,
    arguments: Dict[str, Any],
    timeout: int,
    user: Dict[str, Any],
    ip: str,
    backend_id: Optional[str] = None,
) -> Tuple[bool, Any]:
    """
    Shared tool execution logic for both v1 and mcp endpoints.

    Routing decision (configurable per-service via ROUTING_CONFIG):
    - "connector" → direct API connector (httpx)
    - "backend"   → MCP server or API backend
    - "auto"      → prefer connector, fall back to backend on failure

    Token resolution (per-user credential takes priority):
    1. Look up a user-specific token in the TokenStore for the connector.
    2. Fall back to the shared env-var credential registered at startup.
    """
    allowed, info = state.security.check_request(
        client_id=user["client_id"],
        ip_address=ip,
        user_id=user["user_id"],
    )
    if not allowed:
        raise HTTPException(status_code=429, detail=info)

    valid, sanitized = state.security.validate_and_sanitize(
        tool_name=tool_name,
        arguments=arguments,
    )
    if not valid:
        raise HTTPException(status_code=400, detail=sanitized)

    connector_name = state.connectors._tool_index.get(tool_name)
    resolved_backend_id = backend_id or state.backends._tool_index.get(tool_name)

    async def _resolve_token_async(service_name: str) -> Optional[str]:
        jwt_user_id = user["user_id"]
        token = await get_token_store().get_token(jwt_user_id, service_name)
        if not token:
            token = await get_token_store().get_token("default", service_name)
        return token

    async def _try_connector() -> Tuple[bool, Any]:
        token = await _resolve_token_async(connector_name)
        if not token:
            return False, f"No credentials for '{connector_name}'. Store a token via POST /v1/tokens or set the env var."
        return await state.connectors.call_tool(
            tool_name=tool_name,
            arguments=sanitized,
            user_token=token,
        )

    async def _try_backend() -> Tuple[bool, Any]:
        bid = resolved_backend_id
        if not bid:
            return False, f"Tool '{tool_name}' not found in any backend"
        bstate = state.backends._backends.get(bid)
        token = None
        if bstate and bstate.definition.connector:
            token = await _resolve_token_async(bstate.definition.connector)
            if not token:
                return False, f"No credentials for '{bstate.definition.connector}'. Store a token via POST /v1/tokens or set the env var."
        return await state.backends.call_tool(
            tool_name=tool_name,
            arguments=sanitized,
            backend_id=bid,
            timeout=timeout,
            user_token=token,
        )

    routing = ROUTING_CONFIG.get(connector_name or resolved_backend_id, "auto")

    if routing == "connector":
        if connector_name:
            success, result = await _try_connector()
        elif resolved_backend_id:
            bstate = state.backends._backends.get(resolved_backend_id)
            if bstate and bstate.definition.connector:
                success, result = await _try_backend()
            else:
                success, result = False, f"No connector available for tool '{tool_name}'"
        else:
            success, result = False, f"Tool '{tool_name}' not found"
    elif routing == "backend":
        if resolved_backend_id:
            success, result = await _try_backend()
        elif connector_name:
            success, result = await _try_connector()
        else:
            success, result = False, f"Tool '{tool_name}' not found"
    else:
        if connector_name:
            success, result = await _try_connector()
            if not success and resolved_backend_id:
                success, result = await _try_backend()
        elif resolved_backend_id:
            success, result = await _try_backend()
            if not success and connector_name:
                success, result = await _try_connector()
        else:
            success, result = False, f"Tool '{tool_name}' not found"

    state.security.log_tool_call(
        client_id=user["client_id"],
        user_id=user["user_id"],
        ip_address=ip,
        tool_name=tool_name,
        arguments=arguments,
        success=success,
        result_summary=str(result)[:200] if result else None,
    )

    return success, result


# -----------------------------------------------------------------------------
# Per-User Token Management Endpoints
# -----------------------------------------------------------------------------

class UserTokenRequest(BaseModel):
    """Request body for storing a per-user backend token."""
    connector_name: str
    token: str
    metadata: Optional[Dict[str, Any]] = None


# Connector OAuth configurations
CONNECTOR_OAUTH_CONFIGS = {
    "github": {
        "name": "GitHub",
        "color": "#24292e",
        "icon": "🐙",
        "description": "Access repositories, issues, and pull requests",
    },
    "slack": {
        "name": "Slack",
        "color": "#4A154B",
        "icon": "💬",
        "description": "Send messages and manage channels",
    },
    "linear": {
        "name": "Linear",
        "color": "#5E6AD2",
        "icon": "📋",
        "description": "Issue tracking and project management",
    },
}


@app.get("/connectors", tags=["Token Management"])
async def connectors_page(
    error: Optional[str] = None,
    success: Optional[str] = None,
):
    """
    Connectors listing page - shows all available connectors with Connect buttons.
    
    Clicking Connect redirects to the service's OAuth flow.
    """
    # Check which connectors are already connected
    connected = []
    for conn in CONNECTOR_OAUTH_CONFIGS:
        # For now, check if there's a token in the store
        pass
    
    html = """<!DOCTYPE html>
<html>
<head>
    <title>Connect Services</title>
    <style>
        * { box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f6f8fa; margin: 0; padding: 40px; }
        .container { max-width: 800px; margin: 0 auto; }
        h1 { color: #24292e; margin-bottom: 8px; }
        .subtitle { color: #586069; margin-bottom: 32px; }
        .error { background: #ffeef0; color: #cb2431; padding: 12px 16px; border-radius: 6px; margin-bottom: 16px; }
        .success { background: #dcffe4; color: #22863a; padding: 12px 16px; border-radius: 6px; margin-bottom: 16px; }
        .connectors-grid { display: grid; gap: 16px; }
        .connector-card { background: white; border: 1px solid #e1e4e8; border-radius: 6px; padding: 20px; display: flex; align-items: center; gap: 16px; }
        .connector-card:hover { box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
        .connector-icon { font-size: 32px; width: 48px; height: 48px; display: flex; align-items: center; justify-content: center; }
        .connector-info { flex: 1; }
        .connector-name { font-size: 18px; font-weight: 600; color: #24292e; margin: 0 0 4px 0; }
        .connector-desc { color: #586069; margin: 0; font-size: 14px; }
        .connect-btn { background: #2ea44f; color: white; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-size: 14px; font-weight: 500; text-decoration: none; display: inline-block; }
        .connect-btn:hover { background: #2c974b; }
        .connected-btn { background: #e1e4e8; color: #586069; cursor: default; }
        .connected-badge { background: #dcffe4; color: #22863a; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 500; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Connect Your Services</h1>
        <p class="subtitle">Link your accounts to enable tool access through the gateway.</p>
        
        """ + (f'<div class="error">{html.escape(error)}</div>' if error else '') + """
        """ + (f'<div class="success">{html.escape(success)}</div>' if success else '') + """
        
        <div class="connectors-grid">
"""
    
    for conn_id, conn_config in CONNECTOR_OAUTH_CONFIGS.items():
        html += f"""
            <div class="connector-card">
                <div class="connector-icon">{conn_config['icon']}</div>
                <div class="connector-info">
                    <h3 class="connector-name">{conn_config['name']}</h3>
                    <p class="connector-desc">{conn_config['description']}</p>
                </div>
                <a href="/oauth/authorize/{conn_id}" class="connect-btn">Connect</a>
            </div>
"""
    
    html += """
        </div>
        
        <p style="margin-top: 32px; color: #586069; font-size: 14px;">
            <a href="/docs">View API Documentation</a>
        </p>
    </div>
</body>
</html>"""
    
    return HTMLResponse(content=html)


@app.get("/oauth/authorize/{connector}", tags=["OAuth"])
async def oauth_authorize(connector: str, request: Request):
    """
    Start OAuth flow for a connector.
    
    Redirects to the service's OAuth authorization page.
    Binds the flow to the currently logged-in user.
    """
    app_state = _get_state()
    
    if connector not in CONNECTOR_OAUTH_CONFIGS:
        raise HTTPException(status_code=404, detail=f"Unknown connector: {connector}")
    
    relay_user = get_user_from_session(request)
    relay_user_id = relay_user["id"] if relay_user else None
    
    if connector == "github":
        if not app_state.config.github_oauth.client_id:
            return HTMLResponse(
                content=f"""<html><body>
                    <h1>GitHub OAuth Not Configured</h1>
                    <p>Please set GITHUB_OAUTH_CLIENT_ID and GITHUB_OAUTH_CLIENT_SECRET environment variables.</p>
                    <p><a href="/connectors">Back to Connectors</a></p>
                </body></html>""",
                status_code=501,
            )
        auth_url = app_state.connector_oauth.get_github_auth_url(
            state=app_state.connector_oauth.create_state(connector, user_id=relay_user_id)
        )
    elif connector == "slack":
        if not app_state.config.slack_oauth.client_id:
            return HTMLResponse(
                content=f"""<html><body>
                    <h1>Slack OAuth Not Configured</h1>
                    <p>Please set SLACK_OAUTH_CLIENT_ID and SLACK_OAUTH_CLIENT_SECRET environment variables.</p>
                    <p><a href="/connectors">Back to Connectors</a></p>
                </body></html>""",
                status_code=501,
            )
        auth_url = app_state.connector_oauth.get_slack_auth_url(
            state=app_state.connector_oauth.create_state(connector, user_id=relay_user_id)
        )
    elif connector == "linear":
        if not app_state.config.linear_oauth.client_id:
            return HTMLResponse(
                content=f"""<html><body>
                    <h1>Linear OAuth Not Configured</h1>
                    <p>Please set LINEAR_OAUTH_CLIENT_ID and LINEAR_OAUTH_CLIENT_SECRET environment variables.</p>
                    <p><a href="/connectors">Back to Connectors</a></p>
                </body></html>""",
                status_code=501,
            )
        auth_url = app_state.connector_oauth.get_linear_auth_url(
            state=app_state.connector_oauth.create_state(connector, user_id=relay_user_id)
        )
    else:
        raise HTTPException(status_code=404, detail=f"Unknown connector: {connector}")
    
    return RedirectResponse(url=auth_url)


@app.get("/oauth/github/callback", tags=["OAuth"])
async def github_callback(code: str, state: str = None):
    """Handle GitHub OAuth callback."""
    app_state = _get_state()
    
    state_data = app_state.connector_oauth.validate_state(state)
    if not state_data:
        return HTMLResponse(
            content="<html><body><h1>Invalid State</h1><p>The OAuth state is invalid or expired. <a href='/connectors'>Try again</a></p></body></html>",
            status_code=400,
        )
    
    oauth_user = await app_state.connector_oauth.exchange_github_code(code)
    if not oauth_user:
        return HTMLResponse(
            content="<html><body><h1>Authentication Failed</h1><p>Could not obtain access token from GitHub. <a href='/connectors'>Try again</a></p></body></html>",
            status_code=400,
        )
    
    relay_user_id = state_data.get("user_id") or oauth_user.id
    
    app_state.connector_oauth.store_token("github", relay_user_id, oauth_user)
    
    await get_token_store().set_token(
        user_id=relay_user_id,
        connector_name="github",
        token=oauth_user.access_token,
    )
    
    # Update connector with user's token and run health check
    await app_state.connectors.set_user_token_and_check("github", oauth_user.access_token)
    
    return HTMLResponse(content=f"""<!DOCTYPE html>
<html>
<head>
    <title>Connected</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 500px; margin: 50px auto; padding: 20px; }}
        .success {{ background: #dcffe4; color: #22863a; padding: 16px; border-radius: 6px; }}
        a {{ color: #0366d6; }}
    </style>
</head>
<body>
    <div class="success">
        <h1>GitHub Connected!</h1>
        <p>Welcome, {oauth_user.name or oauth_user.login}!</p>
        <p>Your GitHub account is now linked.</p>
    </div>
    <p><a href="/connectors">Back to Connectors</a> | <a href="/docs">API Docs</a></p>
</body>
</html>""")


@app.get("/oauth/slack/callback", tags=["OAuth"])
async def slack_callback(code: str, state: str = None):
    """Handle Slack OAuth callback."""
    app_state = _get_state()
    
    state_data = app_state.connector_oauth.validate_state(state)
    if not state_data:
        return HTMLResponse(
            content="<html><body><h1>Invalid State</h1><p><a href='/connectors'>Try again</a></p></body></html>",
            status_code=400,
        )
    
    oauth_user = await app_state.connector_oauth.exchange_slack_code(code)
    if not oauth_user:
        return HTMLResponse(
            content="<html><body><h1>Authentication Failed</h1><p><a href='/connectors'>Try again</a></p></body></html>",
            status_code=400,
        )
    
    relay_user_id = state_data.get("user_id") or oauth_user.id
    app_state.connector_oauth.store_token("slack", relay_user_id, oauth_user)
    
    await get_token_store().set_token(
        user_id=relay_user_id,
        connector_name="slack",
        token=oauth_user.access_token,
    )
    
    # Update connector with user's token and run health check
    await app_state.connectors.set_user_token_and_check("slack", oauth_user.access_token)
    
    return HTMLResponse(content=f"""<!DOCTYPE html>
<html>
<head><title>Slack Connected</title></head>
<body>
    <div class="success">
        <h1>Slack Connected!</h1>
        <p>Welcome!</p>
    </div>
    <p><a href="/connectors">Back to Connectors</a></p>
</body>
</html>""")


@app.get("/oauth/linear/callback", tags=["OAuth"])
async def linear_callback(code: str, state: str = None):
    """Handle Linear OAuth callback."""
    app_state = _get_state()
    
    state_data = app_state.connector_oauth.validate_state(state)
    if not state_data:
        return HTMLResponse(
            content="<html><body><h1>Invalid State</h1><p><a href='/connectors'>Try again</a></p></body></html>",
            status_code=400,
        )
    
    oauth_user = await app_state.connector_oauth.exchange_linear_code(code)
    if not oauth_user:
        return HTMLResponse(
            content="<html><body><h1>Authentication Failed</h1><p><a href='/connectors'>Try again</a></p></body></html>",
            status_code=400,
        )
    
    relay_user_id = state_data.get("user_id") or oauth_user.id
    app_state.connector_oauth.store_token("linear", relay_user_id, oauth_user)
    
    await get_token_store().set_token(
        user_id=relay_user_id,
        connector_name="linear",
        token=oauth_user.access_token,
    )
    
    # Update connector with user's token and run health check
    await app_state.connectors.set_user_token_and_check("linear", oauth_user.access_token)
    
    return HTMLResponse(content=f"""<!DOCTYPE html>
<html>
<head><title>Linear Connected</title></head>
<body>
    <div class="success">
        <h1>Linear Connected!</h1>
        <p>Welcome, {oauth_user.name}!</p>
    </div>
    <p><a href="/connectors">Back to Connectors</a></p>
</body>
</html>""")


@app.post("/v1/tokens", tags=["Token Management"])
async def store_user_token(
    req: UserTokenRequest,
    user: Dict = Depends(get_current_user_api_key),
):
    """
    Store a personal API token for a backend connector.

    This allows each authenticated user to supply their own credentials for
    connectors like GitHub, Slack, Linear, etc., so that tool calls are made
    on their behalf rather than using the shared service-account credentials.

    Example:
        curl -X POST https://gateway/v1/tokens \\
          -H "Authorization: Bearer <your_gateway_token>" \\
          -H "Content-Type: application/json" \\
          -d '{"connector_name": "github", "token": "ghp_your_token"}'
    """
    if req.connector_name not in state.connectors.CONNECTOR_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown connector: {req.connector_name}. "
                   f"Valid connectors: {list(state.connectors.CONNECTOR_TYPES.keys())}",
        )
    await get_token_store().set_token(
        user_id=user["user_id"],
        connector_name=req.connector_name,
        token=req.token,
        metadata=req.metadata,
    )
    return {"stored": True, "connector": req.connector_name, "user_id": user["user_id"]}


@app.get("/v1/tokens", tags=["Token Management"])
async def list_user_tokens(user: Dict = Depends(get_current_user_api_key)):
    """List connectors for which the current user has stored a token."""
    connectors = await get_token_store().list_connectors_for_user(user["user_id"])
    return {"user_id": user["user_id"], "connectors": connectors}


@app.delete("/v1/tokens/{connector_name}", tags=["Token Management"])
async def delete_user_token(
    connector_name: str,
    user: Dict = Depends(get_current_user_api_key),
):
    """Remove the stored token for a connector."""
    removed = await get_token_store().delete_token(user["user_id"], connector_name)
    if not removed:
        raise HTTPException(status_code=404, detail=f"No token found for connector: {connector_name}")
    return {"deleted": True, "connector": connector_name}


@app.post("/mcp/call", tags=["MCP Compatible"])
async def call_tool(
    req: ToolCallRequest,
    user: Dict = Depends(get_current_user),
    ip: str = Depends(get_client_ip),
):
    """Call a tool on a backend or connector."""
    success, result = await _execute_tool(
        tool_name=req.tool_name,
        arguments=req.arguments,
        timeout=req.timeout,
        user=user,
        ip=ip,
        backend_id=req.backend_id,
    )
    
    if not success:
        return JSONResponse(
            status_code=400,
            content={"error": result},
        )
    
    return {"success": True, "result": result}


# -----------------------------------------------------------------------------
# MCP Server (FastMCP Integration)
# -----------------------------------------------------------------------------

def create_mcp_server(app_state: Optional["AppState"] = None, init_state: bool = True) -> Optional[Any]:
    """
    Create an MCP server using FastMCP that proxies to registered backends.
    
    This creates an MCP server that Cursor/Claude Code can connect to.
    It dynamically discovers tools from MCP backends and exposes them as native MCP tools.
    
    The server uses OAuth 2.1 JWT authentication:
    - MCP client must initialize with a valid JWT access token
    - Tool calls use the user's stored third-party tokens
    
    Args:
        app_state: Application state with backends and connectors. If None, uses global state.
        init_state: If True and global state is None, initialize it (for standalone MCP mode).
    """
    global state
    
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        logger.error("MCP SDK not installed. Run: pip install mcp")
        return None
    
    config = get_config()
    
    if app_state is None:
        if state is None and init_state:
            logger.info("Initializing state for standalone MCP server")
            app_state = _create_app_state_sync(config)
        else:
            app_state = state
    
    if app_state is None:
        logger.error("Cannot create MCP server: app_state is None. Ensure server is running or init_state=True")
        return None
    
    mcp_host = config.server.mcp_host
    mcp_port = config.server.mcp_port
    
    mcp = FastMCP(
        config.server.server_name,
        instructions=config.server.server_instructions + "\n\n" +
            "Authentication: This server requires OAuth 2.1 JWT access token. " +
            "Clients must obtain a token from the gateway's /oauth/token endpoint " +
            "and pass it during MCP initialization.",
        host=mcp_host,
        port=mcp_port,
        mount_path="/mcp",
        streamable_http_path="/mcp",
        sse_path="/sse",
        message_path="/messages/",
    )
    
    async def _validate_auth(authorization: Optional[str]) -> Optional[Dict[str, Any]]:
        """Validate JWT and return user_info or None."""
        if not authorization or not authorization.startswith("Bearer "):
            return None
        token = authorization[7:]
        user_info = app_state.oauth.validate_access_token(token)
        if not user_info:
            return None
        return user_info
    
    async def _resolve_user_token(user_id: str, service_name: str) -> Optional[str]:
        """Resolve a user's token for a service from the TokenStore."""
        from auth.token_store import get_token_store
        token = await get_token_store().get_token(user_id, service_name)
        if not token:
            token = await get_token_store().get_token("default", service_name)
        return token
    
    async def _execute_discovered_tool(
        tool_name: str,
        arguments: Dict[str, Any],
        authorization: Optional[str],
    ) -> str:
        """Execute a discovered tool with auth and token resolution."""
        user_info = await _validate_auth(authorization)
        if not user_info:
            return json.dumps({"error": "Invalid or missing authorization"})
        
        user_id = user_info.get("user_id")
        
        connector_name = app_state.connectors._tool_index.get(tool_name)
        backend_id = app_state.backends._tool_index.get(tool_name)
        
        if connector_name:
            user_token = await _resolve_user_token(user_id, connector_name)
            if not user_token:
                return json.dumps({
                    "error": f"No credentials for '{connector_name}'",
                    "hint": f"Store a token via POST /v1/tokens or visit /oauth/authorize/{connector_name}",
                })
            success, result = await app_state.connectors.call_tool(
                tool_name=tool_name,
                arguments=arguments,
                user_token=user_token,
            )
        elif backend_id:
            backend_state = app_state.backends._backends.get(backend_id)
            user_token = None
            if backend_state and backend_state.definition.connector:
                user_token = await _resolve_user_token(user_id, backend_state.definition.connector)
                if not user_token:
                    return json.dumps({
                        "error": f"No credentials for '{backend_state.definition.connector}'",
                        "hint": f"Store a token via POST /v1/tokens or visit /oauth/authorize/{backend_state.definition.connector}",
                    })
            success, result = await app_state.backends.call_tool(
                tool_name=tool_name,
                arguments=arguments,
                backend_id=backend_id,
                user_token=user_token,
            )
        else:
            return json.dumps({"error": f"Tool '{tool_name}' not found in any backend or connector"})
        
        if not success:
            return json.dumps({"error": result})
        return json.dumps({"result": result})
    
    # --- Gateway management tools ---
    
    @mcp.tool()
    async def gateway_list_backends(authorization: Optional[str] = None) -> str:
        """List all available backend services and their health status."""
        user_info = await _validate_auth(authorization)
        if not user_info:
            return json.dumps({"error": "Invalid or missing authorization"})
        return json.dumps(app_state.backends.list_backends(), indent=2)

    @mcp.tool()
    async def gateway_list_tools(authorization: Optional[str] = None) -> str:
        """List all available tools across backends and connectors."""
        user_info = await _validate_auth(authorization)
        if not user_info:
            return json.dumps({"error": "Invalid or missing authorization"})
        backend_tools = app_state.backends.list_tools()
        connector_tools = app_state.connectors.get_all_tools()
        return json.dumps({"backend_tools": backend_tools, "connector_tools": connector_tools}, indent=2)

    @mcp.tool()
    async def gateway_connect_backend(backend_id: str, authorization: Optional[str] = None) -> str:
        """Connect to a specific backend service."""
        user_info = await _validate_auth(authorization)
        if not user_info:
            return json.dumps({"error": "Invalid or missing authorization"})
        success, error = await app_state.backends.connect_backend(backend_id)
        if not success:
            return json.dumps({"error": error})
        return json.dumps({"connected": backend_id})

    @mcp.tool()
    async def gateway_auth_status(authorization: Optional[str] = None) -> str:
        """Check authentication and third-party connection status."""
        user_info = await _validate_auth(authorization)
        if not user_info:
            return json.dumps({"error": "Invalid or missing authorization"})
        user_id = user_info.get("user_id")
        from auth.token_store import get_token_store
        connected = await get_token_store().list_connectors_for_user(user_id)
        return json.dumps({
            "user_id": user_id,
            "connected_services": connected,
            "auth_endpoint": "http://localhost:8000/oauth/authorize/{connector}",
        }, indent=2)
    
    # --- Dynamically discovered tools from MCP backends ---
    # Instead of hardcoding tool wrappers, we discover tools from connected
    # MCP backends and expose them as native MCP tools via a generic dispatcher.
    # This is the MCP discovery pattern: tools are discovered at runtime.
    
    @mcp.tool()
    async def gateway_call_tool(
        tool_name: str,
        arguments: str = "{}",
        authorization: Optional[str] = None,
    ) -> str:
        """Call any tool discovered from backends or connectors.
        
        Use gateway_list_tools to see available tools first.
        
        Args:
            tool_name: Name of the tool to call
            arguments: JSON string of tool arguments
            authorization: JWT access token (Bearer <token>)
        """
        try:
            args = json.loads(arguments) if isinstance(arguments, str) else arguments
        except json.JSONDecodeError:
            return json.dumps({"error": "Invalid JSON in arguments"})
        return await _execute_discovered_tool(tool_name, args, authorization)
    
    return mcp


# -----------------------------------------------------------------------------
# Per-Connector MCP Servers
# -----------------------------------------------------------------------------

def create_connector_mcp_server(
    connector_name: str,
    app_state: Optional["AppState"] = None,
) -> Optional[Any]:
    """
    Create an MCP server that exposes all tools from a single connector
    as native MCP tools.

    Each connector (github, slack, linear, openai, anthropic) gets its own
    FastMCP instance with proper tool schemas and native discovery.

    Args:
        connector_name: Name of the connector (e.g. "github", "slack")
        app_state: Application state. If None, uses global state.
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        logger.error("MCP SDK not installed. Run: pip install mcp")
        return None

    if app_state is None:
        app_state = state

    if app_state is None:
        logger.error("Cannot create connector MCP server: app_state is None")
        return None

    connector = app_state.connectors.get_connector(connector_name)
    if connector is None:
        logger.error(f"Connector '{connector_name}' not found")
        return None

    tools = []
    if hasattr(connector, "get_tools_async"):
        try:
            import asyncio
            tools = asyncio.get_event_loop().run_until_complete(connector.get_tools_async())
        except Exception as e:
            logger.warning(f"Async tool discovery failed for '{connector_name}': {e}")
            tools = connector.get_tools()
    else:
        tools = connector.get_tools()
    
    if not tools:
        logger.warning(f"Connector '{connector_name}' has no tools")
        return None

    mcp = FastMCP(
        f"gateway-{connector_name}",
        instructions=f"{connector.display_name}: {connector.description}",
    )

    for tool_def in tools:
        tool_name = tool_def.name
        tool_desc = tool_def.description
        tool_params = tool_def.parameters

        schema_params = tool_params.get("properties", {})
        required = tool_params.get("required", [])

        params = []
        for pname in schema_params:
            if pname in required:
                params.append(f"{pname}: str")
        for pname in schema_params:
            if pname not in required:
                params.append(f"{pname}: Optional[str] = None")
        if params:
            params_str = ", ".join(params) + ", ctx: Context = None"
        else:
            params_str = "ctx: Context = None"

        fn_code = f"""
async def tool_fn({params_str}) -> str:
    _tool_param_names = {list(schema_params.keys())}
    kwargs = {{k: v for k, v in locals().items() if k in _tool_param_names and v is not None}}

    # Try to get authorization from MCP request context
    auth_val = None
    api_key = None
    user_id = None
    try:
        if ctx is not None and ctx.request_context is not None:
            req = ctx.request_context.request
            if req is not None:
                auth_val = req.headers.get("Authorization")
                api_key = req.headers.get("X-API-Key")
                user_id = req.headers.get("X-User-Id")
    except Exception:
        pass

    user_token = None
    
    # First try X-User-Id header (set by per-user MCP endpoint)
    if user_id:
        try:
            from auth.token_store import get_token_store
            user_token = await get_token_store().get_token(user_id, "{connector_name}")
        except Exception:
            pass
    
    # Then try API key header
    if not user_token and api_key:
        try:
            from auth.database import get_api_key
            key_data = get_api_key(api_key)
            if key_data:
                user_id = key_data["user_id"]
                from auth.token_store import get_token_store
                user_token = await get_token_store().get_token(user_id, "{connector_name}")
        except Exception:
            pass
    
    # Then try JWT auth
    if not user_token and auth_val:
        token = auth_val[7:] if auth_val.startswith("Bearer ") else auth_val
        user_info = app_state.oauth.validate_access_token(token)
        if user_info:
            user_id = user_info.get("user_id")
            try:
                from auth.token_store import get_token_store
                user_token = await get_token_store().get_token(user_id, "{connector_name}")
            except Exception:
                pass

    requires_auth = {tool_def.requires_auth}
    if requires_auth and not user_token:
        return json.dumps({{
            "error": f"No credentials for '{connector_name}'",
            "hint": "Connect your account at http://localhost:8000/oauth/authorize/{connector_name}",
        }})

    success, result = await app_state.connectors.call_tool(
        tool_name="{tool_name}",
        arguments=kwargs,
        user_token=user_token,
    )

    if not success:
        return json.dumps({{"error": result}})
    return json.dumps({{"result": result}})
"""
        local_ns: Dict[str, Any] = {
            "app_state": app_state,
            "json": json,
            "Optional": Optional,
            "Context": None,
        }
        try:
            from mcp.server.fastmcp import Context
            local_ns["Context"] = Context
        except ImportError:
            pass

        exec(fn_code, local_ns, local_ns)
        tool_fn = local_ns["tool_fn"]
        tool_fn.__name__ = tool_name
        tool_fn.__doc__ = tool_desc

        mcp.tool()(tool_fn)

    # Add resources
    resources = connector.get_resources()
    for resource in resources:
        resource_uri = resource.uri
        resource_name = resource.name
        resource_desc = resource.description
        
        @mcp.resource(resource_uri)
        async def resource_handler() -> str:
            result = await connector.read_resource(resource_uri)
            return json.dumps(result) if result else "{}"
        
        resource_handler.__name__ = resource_name
        resource_handler.__doc__ = resource_desc
    
    # Add prompts
    prompts = connector.get_prompts()
    for prompt in prompts:
        prompt_name = prompt.name
        prompt_desc = prompt.description
        prompt_template = prompt.template
        
        @mcp.prompt(name=prompt_name)
        def prompt_handler(**kwargs) -> str:
            result = prompt_template
            for key, value in kwargs.items():
                result = result.replace(f"{{{key}}}", str(value))
            return result
        
        prompt_handler.__doc__ = prompt_desc
    
    return mcp


def create_connector_mcp_server_with_auth(
    connector_name: str,
    user_token: Optional[str] = None,
    app_state: Optional["AppState"] = None,
) -> Optional[Any]:
    """
    Create an MCP server for a specific user with pre-fetched token.
    
    The server uses the provided user_token to make tool calls.
    
    Args:
        connector_name: Name of the connector (e.g. "github", "slack")
        user_token: The pre-fetched user token for this connector
        app_state: Application state. If None, uses global state.
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        logger.error("MCP SDK not installed. Run: pip install mcp")
        return None

    if app_state is None:
        app_state = state

    if app_state is None:
        logger.error("Cannot create connector MCP server: app_state is None")
        return None

    connector = app_state.connectors.get_connector(connector_name)
    if connector is None:
        logger.error(f"Connector '{connector_name}' not found")
        return None

    tools = []
    if hasattr(connector, "get_tools_async"):
        try:
            import asyncio
            tools = asyncio.get_event_loop().run_until_complete(connector.get_tools_async())
        except Exception as e:
            logger.warning(f"Async tool discovery failed for '{connector_name}': {e}")
            tools = connector.get_tools()
    else:
        tools = connector.get_tools()
    
    if not tools:
        logger.warning(f"Connector '{connector_name}' has no tools")
        return None

    mcp = FastMCP(
        f"gateway-{connector_name}",
        instructions=f"{connector.display_name}: {connector.description}",
    )

    # Use the provided user_token (already fetched in the endpoint)
    # This avoids async event loop issues

    for tool_def in tools:
        tool_name = tool_def.name
        tool_desc = tool_def.description
        tool_params = tool_def.parameters

        schema_params = tool_params.get("properties", {})
        required = tool_params.get("required", [])

        params = []
        for pname in schema_params:
            if pname in required:
                params.append(f"{pname}: str")
        for pname in schema_params:
            if pname not in required:
                params.append(f"{pname}: Optional[str] = None")
        if params:
            params_str = ", ".join(params) + ", ctx: Context = None"
        else:
            params_str = "ctx: Context = None"

        # Capture user_token in closure
        _user_token = user_token
        _connector_name = connector_name

        fn_code = f"""
async def tool_fn({params_str}) -> str:
    _tool_param_names = {list(schema_params.keys())}
    kwargs = {{k: v for k, v in locals().items() if k in _tool_param_names and v is not None}}

    user_token = "{_user_token or ''}"
    
    if not user_token:
        return json.dumps({{
            "error": f"No credentials for '{_connector_name}'",
            "hint": "Connect your account at http://localhost:8000/oauth/authorize/{_connector_name}",
        }})

    success, result = await app_state.connectors.call_tool(
        tool_name="{tool_name}",
        arguments=kwargs,
        user_token=user_token,
    )

    if not success:
        return json.dumps({{"error": result}})
    return json.dumps({{"result": result}})
"""
        local_ns: Dict[str, Any] = {
            "app_state": app_state,
            "json": json,
            "Optional": Optional,
            "Context": None,
            "asyncio": asyncio,
        }
        try:
            from mcp.server.fastmcp import Context
            local_ns["Context"] = Context
        except ImportError:
            pass

        exec(fn_code, local_ns, local_ns)
        tool_fn = local_ns["tool_fn"]
        tool_fn.__name__ = tool_name
        tool_fn.__doc__ = tool_desc

        mcp.tool()(tool_fn)

    # Add resources
    resources = connector.get_resources()
    for resource in resources:
        resource_uri = resource.uri
        resource_name = resource.name
        resource_desc = resource.description
        
        @mcp.resource(resource_uri)
        async def resource_handler() -> str:
            result = await connector.read_resource(resource_uri)
            return json.dumps(result) if result else "{}"
        
        resource_handler.__name__ = resource_name
        resource_handler.__doc__ = resource_desc
    
    # Add prompts
    prompts = connector.get_prompts()
    for prompt in prompts:
        prompt_name = prompt.name
        prompt_desc = prompt.description
        prompt_template = prompt.template
        
        @mcp.prompt(name=prompt_name)
        def prompt_handler(**kwargs) -> str:
            result = prompt_template
            for key, value in kwargs.items():
                result = result.replace(f"{{{key}}}", str(value))
            return result
        
        prompt_handler.__doc__ = prompt_desc
    
    return mcp
    """
    Create an MCP server that proxies directly to a specific MCP backend.
    
    This is useful when you want Cursor to connect directly to the gateway
    and have it proxy all MCP calls to the underlying MCP server.
    
    Args:
        backend_id: The backend to proxy to (default: github)
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        logger.error("MCP SDK not installed. Run: pip install mcp")
        return None
    
    config = get_config()
    
    def get_backend_tools():
        """Get tools from the backend."""
        return state.backends.list_tools()
    
    mcp = FastMCP(
        f"relay-{backend_id}",
        instructions=f"Relay proxying to {backend_id} backend",
    )

    @mcp.tool()
    async def proxy_call(tool_name: str, arguments: str = "{}") -> str:
        """
        Call a tool on the proxied backend.
        
        Args:
            tool_name: Name of the tool to call
            arguments: JSON string of arguments
        """
        try:
            args = json.loads(arguments) if isinstance(arguments, str) else arguments
        except json.JSONDecodeError:
            return json.dumps({"error": "Invalid JSON arguments"})
        
        success, result = await state.backends.call_tool(
            tool_name=tool_name,
            arguments=args,
            backend_id=backend_id,
        )
        
        if not success:
            return json.dumps({"error": result})
        return json.dumps({"result": result}, indent=2)

    return mcp


def run_mcp_proxy(backend_id: str = "github"):
    """
    Run the gateway as an MCP proxy to a specific backend.
    
    This starts an stdio MCP server that proxies all requests to the configured backend.
    Useful for testing MCP client connections.
    """
    async def main():
        config = get_config()
        
        logger.info(f"Starting MCP proxy for backend: {backend_id}")
        
        backends = BackendManager(
            health_check_interval=config.backend.health_check_interval_seconds,
            unhealthy_threshold=config.backend.unhealthy_threshold,
        )
        
        for backend_id_def, backend_def in BACKEND_DEFINITIONS.items():
            if backend_def["type"] == "mcp":
                backend_type = BackendType.MCP_STDIO
            elif backend_def.get("api_type") == "graphql":
                backend_type = BackendType.API_GRAPHQL
            else:
                backend_type = BackendType.API_REST

            _env_val = os.getenv(backend_def["env_key"]) if backend_def.get("env_key") else None
            _env = {backend_def["env_key"]: _env_val} if _env_val else {}

            definition = BackendDefinition(
                id=backend_id_def,
                name=backend_def["name"],
                description=backend_def["description"],
                backend_type=backend_type,
                enabled=True,
                requires_auth=backend_def.get("requires_auth", False),
                env_key=backend_def.get("env_key"),
                connector=backend_def.get("connector"),
                tools=backend_def.get("tools", []),
                command=backend_def.get("command"),
                args=backend_def.get("args", []),
                env=_env,
                url=backend_def.get("url"),
                base_url=backend_def.get("base_url"),
                auth_type=backend_def.get("auth_type"),
            )
            backends.register_backend(definition)
        
        await backends.start()
        
        if backend_id not in backends._backends:
            logger.error(f"Backend {backend_id} not found. Available: {list(backends._backends.keys())}")
            return
        
        logger.info(f"Connecting to backend: {backend_id}")
        success, error = await backends.connect_backend(backend_id)
        if not success:
            logger.error(f"Failed to connect to {backend_id}: {error}")
            return
        
        logger.info(f"Connected to {backend_id}, ready for MCP proxy")
        
        try:
            from mcp.server import Server
            from mcp.types import Tool, TextContent
            from mcp.server.stdio import stdio_server
            
            server = Server(f"relay-proxy-{backend_id}")
            
            @server.list_tools()
            async def list_tools():
                tools = backends.list_tools()
                return [
                    Tool(
                        name=t["name"],
                        description=t.get("backend_name", "MCP tool"),
                        inputSchema=t.get("inputSchema", {}),
                    )
                    for t in tools
                ]
            
            @server.call_tool()
            async def call_tool(name: str, arguments: dict):
                success, result = await backends.call_tool(
                    tool_name=name,
                    arguments=arguments,
                    backend_id=backend_id,
                )
                if not success:
                    return [TextContent(type="text", text=f"Error: {result}")]
                return [TextContent(type="text", text=str(result))]
            
            async def run():
                async with stdio_server(server) as (read, write):
                    logger.info("MCP proxy running on stdio")
                    while True:
                        await asyncio.sleep(1)
            
            await run()
        except Exception as e:
            logger.error(f"MCP proxy error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            await backends.stop()

    asyncio.run(main())


# -----------------------------------------------------------------------------
# Entry Point
# -----------------------------------------------------------------------------

def run_server():
    """Run the Relay server."""
    import uvicorn
    
    config = get_config()
    
    # Run FastAPI server
    uvicorn.run(
        "gateway.server:app",
        host=config.server.host,
        port=config.server.port,
        workers=config.server.workers,
        reload=config.is_development,
    )


def run_mcp_server(transport: str = "stdio", port: int = None):
    """Run the MCP server.
    
    Args:
        transport: Transport type - "stdio", "sse", or "streamable-http"
        port: Port for SSE/streamable-http (defaults to 8001)
    """
    mcp = create_mcp_server()
    if mcp:
        if transport == "stdio":
            mcp.run(transport=transport)
        else:
            # For SSE/streamable-http, the port is set in create_mcp_server via config
            # Just run with the mount_path
            mcp.run(transport=transport, mount_path="/mcp")
            # Note: FastMCP run() is blocking and manages its own server
            # For production, consider running MCP as separate process


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Relay Server")
    parser.add_argument(
        "mode",
        choices=["http", "mcp"],
        default="http",
        help="Server mode: http (FastAPI) or mcp (FastMCP stdio)",
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse", "streamable-http"],
        default="stdio",
        help="MCP transport type (only for mcp mode)",
    )
    args = parser.parse_args()
    
    # Setup logging
    logging.basicConfig(
        level=logging.DEBUG if os.getenv("DEBUG") else logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    
    if args.mode == "http":
        run_server()
    else:
        run_mcp_server(transport=args.transport)

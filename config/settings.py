"""
Relay Configuration

Centralized settings using Pydantic for validation and environment variable support.
"""

from __future__ import annotations

import os
import secrets
from typing import Any, Dict, List, Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class OAuthSettings(BaseSettings):
    """OAuth 2.1 server configuration."""

    model_config = SettingsConfigDict(env_prefix="OAUTH_")

    # JWT signing
    jwt_secret_key: str = Field(default_factory=lambda: secrets.token_urlsafe(32))
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    code_expire_minutes: int = 10

    # Code verifier length
    code_verifier_length: int = 128

    # OAuth server endpoints
    authorization_endpoint: str = "/oauth/authorize"
    token_endpoint: str = "/oauth/token"
    revoke_endpoint: str = "/oauth/revoke"

    # Allowed redirect URIs (for validation)
    allowed_redirect_uris: List[str] = Field(default_factory=lambda: [
        "http://localhost:*",
        "https://claude.ai/*",
        "https://cursor.sh/*",
        "vscode://*",
        "cursor://*",
    ])


class ConnectorOAuthConfig(BaseSettings):
    """OAuth configuration for a single connector."""
    
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    auth_url: Optional[str] = None
    token_url: Optional[str] = None
    scopes: List[str] = Field(default_factory=list)
    callback_url: str = "http://localhost:8000/oauth/callback"


class GitHubOAuthSettings(BaseSettings):
    """GitHub OAuth configuration."""
    
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    scopes: List[str] = Field(default_factory=lambda: ["repo", "read:user"])
    callback_url: str = "http://localhost:8000/oauth/github/callback"


class SlackOAuthSettings(BaseSettings):
    """Slack OAuth configuration."""
    
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    scopes: List[str] = Field(default_factory=lambda: ["chat:write", "channels:read"])
    callback_url: str = "http://localhost:8000/oauth/slack/callback"


class LinearOAuthSettings(BaseSettings):
    """Linear OAuth configuration."""
    
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    scopes: List[str] = Field(default_factory=lambda: ["read", "write"])
    callback_url: str = "http://localhost:8000/oauth/linear/callback"


class GitHubOAuthSettings(BaseSettings):
    """GitHub OAuth configuration for third-party service auth."""

    model_config = SettingsConfigDict(env_prefix="GITHUB_OAUTH_")

    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    scopes: List[str] = Field(default_factory=lambda: ["repo", "read:user"])
    callback_url: str = "http://localhost:8000/oauth/github/callback"


class SecuritySettings(BaseSettings):
    """Security and rate limiting configuration."""

    model_config = SettingsConfigDict(env_prefix="SECURITY_")

    # Rate limiting
    rate_limit_enabled: bool = True
    rate_limit_requests_per_minute: int = 60
    rate_limit_requests_per_hour: int = 1000

    # Request validation
    max_request_size_bytes: int = 10 * 1024 * 1024  # 10 MB
    max_tool_call_depth: int = 5
    request_timeout_seconds: int = 300

    # Input sanitization
    sanitize_html: bool = True
    max_string_length: int = 100000

    # Audit logging
    audit_enabled: bool = True
    audit_log_path: str = "logs/audit.log"
    audit_sensitive_fields: List[str] = Field(default_factory=lambda: [
        "password", "token", "secret", "key", "credential", "api_key"
    ])

    # IP restrictions
    ip_whitelist: List[str] = Field(default_factory=list)
    ip_blacklist: List[str] = Field(default_factory=list)


class BackendSettings(BaseSettings):
    """Backend MCP server and API configuration."""

    model_config = SettingsConfigDict(env_prefix="BACKEND_")

    # Connection settings
    connect_timeout_seconds: int = 30
    tool_timeout_seconds: int = 120
    max_concurrent_connections: int = 100

    # Retry settings
    max_retries: int = 3
    retry_backoff_base: float = 1.5

    # Health checks
    health_check_interval_seconds: int = 30
    unhealthy_threshold: int = 3


class ServerSettings(BaseSettings):
    """Main server configuration."""

    model_config = SettingsConfigDict(env_prefix="SERVER_")

    # Server binding
    host: str = "0.0.0.0"
    port: int = 8000
    workers: int = 1

    # MCP SSE server binding (separate from main HTTP server)
    mcp_host: str = "127.0.0.1"
    mcp_port: int = 8001

    # TLS/SSL
    ssl_enabled: bool = False
    ssl_cert_path: Optional[str] = None
    ssl_key_path: Optional[str] = None

    # CORS
    cors_origins: List[str] = Field(default_factory=lambda: ["*"])
    cors_methods: List[str] = Field(default_factory=lambda: ["GET", "POST", "OPTIONS"])
    cors_headers: List[str] = Field(default_factory=lambda: ["*"])

    # MCP Server info
    server_name: str = "relay"
    server_version: str = "0.1.0"
    server_instructions: str = (
        "Relay - OAuth-authenticated proxy for connecting to "
        "third-party MCP servers and APIs. Use tools to discover "
        "backends and route requests through this gateway."
    )


class DatabaseSettings(BaseSettings):
    """Database configuration for persistence."""

    model_config = SettingsConfigDict(env_prefix="DATABASE_")

    # SQLite (default, local development)
    sqlite_path: str = "data/gateway.db"

    # Redis (for rate limiting, sessions, caching)
    redis_url: Optional[str] = None
    redis_prefix: str = "relay:"


class RelayConfig(BaseSettings):
    """
    Master configuration for Relay.

    Loads from environment variables with sensible defaults.
    """

    model_config = SettingsConfigDict(
        env_prefix="RELAY_",
        env_nested_delimiter="__",
        case_sensitive=False,
    )

    # Environment
    environment: str = Field(default="development")

    # Sub-configurations
    oauth: OAuthSettings = Field(default_factory=OAuthSettings)
    github_oauth: GitHubOAuthSettings = Field(default_factory=GitHubOAuthSettings)
    slack_oauth: SlackOAuthSettings = Field(default_factory=SlackOAuthSettings)
    linear_oauth: LinearOAuthSettings = Field(default_factory=LinearOAuthSettings)
    security: SecuritySettings = Field(default_factory=SecuritySettings)
    backend: BackendSettings = Field(default_factory=BackendSettings)
    server: ServerSettings = Field(default_factory=ServerSettings)
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)

    # Debug mode
    debug: bool = False

    @field_validator("environment")
    @classmethod
    def validate_environment(cls, v: str) -> str:
        allowed = {"development", "staging", "production"}
        if v not in allowed:
            raise ValueError(f"environment must be one of {allowed}")
        return v

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def is_development(self) -> bool:
        return self.environment == "development"


_config_cache: Optional[RelayConfig] = None


def get_config(force_reload: bool = False) -> RelayConfig:
    """
    Get cached configuration instance.
    
    Args:
        force_reload: If True, bypass cache and reload from environment
    """
    global _config_cache
    if _config_cache is None or force_reload:
        _config_cache = RelayConfig(_env_file=".env")
    return _config_cache


def clear_config_cache() -> None:
    """Clear the cached configuration (useful for testing)."""
    global _config_cache
    _config_cache = None


# Backend definitions - these are the third-party services we proxy to
# The 'connector' field maps to the OAuth connector for per-user token auth
BACKEND_DEFINITIONS: Dict[str, Dict[str, Any]] = {
    "relay-github": {
        "type": "mcp",
        "name": "Relay GitHub",
        "description": "Relay GitHub MCP server",
        "url": "http://localhost:8000/mcp/github/mcp",
        "connector": "github",
        "tools": [],
        "requires_auth": True,
    },
    # Example MCP servers
    "github": {
        "type": "mcp",
        "name": "GitHub",
        "description": "GitHub API via MCP server",
        "command": "npx",
        "args": ["-y", "@modelcontextprotocol/server-github"],
        "env_key": "GITHUB_PERSONAL_ACCESS_TOKEN",
        "connector": "github",  # Maps to OAuth connector for per-user tokens
        "tools": [],  # Populated dynamically from MCP discovery
        "requires_auth": True,
    },
    "filesystem": {
        "type": "mcp",
        "name": "Filesystem",
        "description": "Local filesystem access via MCP server",
        "command": "npx",
        "args": ["-y", "@modelcontextprotocol/server-filesystem", "${ALLOWED_DIRS:-/tmp}"],
        "tools": [],  # Populated dynamically from MCP discovery
        "requires_auth": False,
    },
    "postgres": {
        "type": "mcp",
        "name": "PostgreSQL",
        "description": "PostgreSQL database via MCP server",
        "command": "npx",
        "args": ["-y", "@modelcontextprotocol/server-postgres"],
        "env_key": "DATABASE_URL",
        "tools": [],  # Populated dynamically from MCP discovery
        "requires_auth": True,
    },
    # Example direct API backends
    "openai": {
        "type": "api",
        "api_type": "rest",
        "name": "OpenAI",
        "description": "OpenAI API direct integration",
        "base_url": "https://api.openai.com/v1",
        "env_key": "OPENAI_API_KEY",
        "connector": "openai",
        "auth_type": "bearer",
        "tools": [],  # Populated from connector definitions
        "requires_auth": True,
    },
    "anthropic": {
        "type": "api",
        "api_type": "rest",
        "name": "Anthropic",
        "description": "Anthropic Claude API direct integration",
        "base_url": "https://api.anthropic.com/v1",
        "env_key": "ANTHROPIC_API_KEY",
        "connector": "anthropic",
        "auth_type": "x-api-key",
        "tools": [],  # Populated from connector definitions
        "requires_auth": True,
    },
    "slack": {
        "type": "api",
        "api_type": "rest",
        "name": "Slack",
        "description": "Slack API direct integration",
        "base_url": "https://slack.com/api",
        "env_key": "SLACK_BOT_TOKEN",
        "connector": "slack",
        "auth_type": "bearer",
        "tools": [],  # Populated from connector definitions
        "requires_auth": True,
    },
    "linear": {
        "type": "api",
        "api_type": "graphql",
        "name": "Linear",
        "description": "Linear API via GraphQL",
        "base_url": "https://api.linear.app/graphql",
        "env_key": "LINEAR_API_KEY",
        "connector": "linear",
        "auth_type": "bearer",
        "tools": [],  # Populated from connector definitions
        "requires_auth": True,
    },
}

# Routing configuration: per-service routing preference
# "connector" = use direct API connector (httpx)
# "backend" = use MCP server or API backend
# "auto" = prefer connector, fall back to backend if connector fails
ROUTING_CONFIG: Dict[str, str] = {
    "github": "connector",
    "slack": "connector",
    "linear": "connector",
    "openai": "connector",
    "anthropic": "connector",
    "filesystem": "backend",
    "postgres": "backend",
}

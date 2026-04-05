"""
OAuth Provider for Third-Party Connectors

Manages OAuth flows for GitHub, Slack, Linear, and other connectors.
Each connector can have its own OAuth configuration.
"""

from __future__ import annotations

import secrets
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import httpx

from config.settings import RelayConfig


@dataclass
class OAuthUser:
    """OAuth user info."""
    id: str
    name: Optional[str]
    email: Optional[str]
    access_token: str
    refresh_token: Optional[str] = None
    expires_at: Optional[datetime] = None


class OAuthProvider:
    """
    Generic OAuth provider that supports multiple services.
    """
    
    def __init__(self, config: RelayConfig):
        self.config = config
        
        # In-memory stores (use Redis in production)
        self._states: Dict[str, Dict[str, Any]] = {}
        self._tokens: Dict[str, Dict[str, OAuthUser]] = {}  # connector -> user_id -> OAuthUser
    
    # -------------------------------------------------------------------------
    # GitHub OAuth
    # -------------------------------------------------------------------------
    
    def get_github_auth_url(self, state: str) -> str:
        """Get GitHub OAuth authorization URL."""
        cfg = self.config.github_oauth
        params = {
            "client_id": cfg.client_id,
            "redirect_uri": cfg.callback_url,
            "scope": " ".join(cfg.scopes),
            "state": state,
        }
        return f"https://github.com/login/oauth/authorize?{urllib.parse.urlencode(params)}"
    
    async def exchange_github_code(self, code: str) -> Optional[OAuthUser]:
        """Exchange GitHub code for access token."""
        cfg = self.config.github_oauth
        if not cfg.client_id or not cfg.client_secret:
            return None
        
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    "https://github.com/login/oauth/access_token",
                    json={
                        "client_id": cfg.client_id,
                        "client_secret": cfg.client_secret,
                        "code": code,
                    },
                    headers={"Accept": "application/json"},
                )
                if response.status_code == 200:
                    data = response.json()
                    access_token = data.get("access_token")
                    if access_token:
                        return await self._get_github_user(access_token)
            except Exception:
                pass
        return None
    
    async def _get_github_user(self, access_token: str) -> Optional[OAuthUser]:
        """Get user info from GitHub API."""
        async with httpx.AsyncClient() as client:
            try:
                user_resp = await client.get(
                    "https://api.github.com/user",
                    headers={
                        "Authorization": f"Bearer {access_token}",
                        "Accept": "application/vnd.github.v3+json",
                    },
                )
                if user_resp.status_code != 200:
                    return None
                
                user_data = user_resp.json()
                
                # Get email
                email = user_data.get("email")
                if not email:
                    emails_resp = await client.get(
                        "https://api.github.com/user/emails",
                        headers={
                            "Authorization": f"Bearer {access_token}",
                            "Accept": "application/vnd.github.v3+json",
                        },
                    )
                    if emails_resp.status_code == 200:
                        for e in emails_resp.json():
                            if e.get("primary"):
                                email = e.get("email")
                                break
                
                return OAuthUser(
                    id=str(user_data["id"]),
                    name=user_data.get("name"),
                    email=email,
                    access_token=access_token,
                )
            except Exception:
                pass
        return None
    
    # -------------------------------------------------------------------------
    # Slack OAuth
    # -------------------------------------------------------------------------
    
    def get_slack_auth_url(self, state: str) -> str:
        """Get Slack OAuth authorization URL."""
        cfg = self.config.slack_oauth
        params = {
            "client_id": cfg.client_id,
            "redirect_uri": cfg.callback_url,
            "scope": ",".join(cfg.scopes),
            "state": state,
        }
        return f"https://slack.com/oauth/v2/authorize?{urllib.parse.urlencode(params)}"
    
    async def exchange_slack_code(self, code: str) -> Optional[OAuthUser]:
        """Exchange Slack code for access token."""
        cfg = self.config.slack_oauth
        if not cfg.client_id or not cfg.client_secret:
            return None
        
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    "https://slack.com/api/oauth.v2.access",
                    data={
                        "client_id": cfg.client_id,
                        "client_secret": cfg.client_secret,
                        "code": code,
                        "redirect_uri": cfg.callback_url,
                    },
                )
                if response.status_code == 200:
                    data = response.json()
                    if data.get("ok"):
                        return OAuthUser(
                            id=data.get("authed_user", {}).get("id", ""),
                            name=data.get("authed_user", {}).get("name"),
                            email=data.get("authed_user", {}).get("email"),
                            access_token=data.get("access_token"),
                        )
            except Exception:
                pass
        return None
    
    # -------------------------------------------------------------------------
    # Linear OAuth
    # -------------------------------------------------------------------------
    
    def get_linear_auth_url(self, state: str) -> str:
        """Get Linear OAuth authorization URL."""
        cfg = self.config.linear_oauth
        params = {
            "client_id": cfg.client_id,
            "redirect_uri": cfg.callback_url,
            "scope": " ".join(cfg.scopes),
            "state": state,
        }
        return f"https://linear.app/oauth/authorize?{urllib.parse.urlencode(params)}"
    
    async def exchange_linear_code(self, code: str) -> Optional[OAuthUser]:
        """Exchange Linear code for access token."""
        cfg = self.config.linear_oauth
        if not cfg.client_id or not cfg.client_secret:
            return None
        
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    "https://api.linear.app/oauth/token",
                    json={
                        "client_id": cfg.client_id,
                        "client_secret": cfg.client_secret,
                        "code": code,
                        "redirect_uri": cfg.callback_url,
                        "grant_type": "authorization_code",
                    },
                )
                if response.status_code == 200:
                    data = response.json()
                    access_token = data.get("access_token")
                    if access_token:
                        return await self._get_linear_user(access_token)
            except Exception:
                pass
        return None
    
    async def _get_linear_user(self, access_token: str) -> Optional[OAuthUser]:
        """Get user info from Linear API."""
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    "https://api.linear.app/graphql",
                    json={
                        "query": "query { viewer { id name email } }"
                    },
                    headers={
                        "Authorization": f"Bearer {access_token}",
                        "Content-Type": "application/json",
                    },
                )
                if response.status_code == 200:
                    data = response.json()
                    viewer = data.get("data", {}).get("viewer", {})
                    if viewer:
                        return OAuthUser(
                            id=viewer.get("id", ""),
                            name=viewer.get("name"),
                            email=viewer.get("email"),
                            access_token=access_token,
                        )
            except Exception:
                pass
        return None
    
    # -------------------------------------------------------------------------
    # Generic OAuth State Management
    # -------------------------------------------------------------------------
    
    def create_state(self, connector: str, user_id: Optional[str] = None) -> str:
        """Create a new OAuth state."""
        state = secrets.token_urlsafe(32)
        self._states[state] = {
            "connector": connector,
            "user_id": user_id,
            "created_at": datetime.now(timezone.utc),
        }
        return state
    
    def validate_state(self, state: str) -> Optional[Dict[str, Any]]:
        """Validate and consume an OAuth state."""
        if state not in self._states:
            return None
        
        state_data = self._states[state]
        created = state_data["created_at"]
        
        if datetime.now(timezone.utc) - created > timedelta(minutes=10):
            del self._states[state]
            return None
        
        return state_data
    
    # -------------------------------------------------------------------------
    # Token Management
    # -------------------------------------------------------------------------
    
    def store_token(self, connector: str, user_id: str, oauth_user: OAuthUser) -> None:
        """Store OAuth token for a user."""
        if connector not in self._tokens:
            self._tokens[connector] = {}
        self._tokens[connector][user_id] = oauth_user
    
    def get_token(self, connector: str, user_id: str) -> Optional[str]:
        """Get access token for a user."""
        user = self._tokens.get(connector, {}).get(user_id)
        return user.access_token if user else None
    
    def get_connector_token(self, connector: str, user_id: str) -> Optional[OAuthUser]:
        """Get full OAuth user object."""
        return self._tokens.get(connector, {}).get(user_id)
    
    def remove_token(self, connector: str, user_id: str) -> bool:
        """Remove token for a user."""
        if connector in self._tokens and user_id in self._tokens[connector]:
            del self._tokens[connector][user_id]
            return True
        return False
    
    def has_token(self, connector: str, user_id: str) -> bool:
        """Check if user has token for connector."""
        return connector in self._tokens and user_id in self._tokens[connector]


def create_oauth_provider(config: RelayConfig) -> OAuthProvider:
    """Create OAuth provider from config."""
    return OAuthProvider(config=config)

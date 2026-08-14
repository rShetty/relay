"""
CSRF protection middleware for web UI forms.

Uses double-submit cookie pattern:
1. On GET requests, a CSRF token cookie is set
2. On POST/PUT/DELETE form requests, the token must be present
   in both the cookie and a hidden form field / header
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from typing import Optional

from starlette.middleware.base import BaseHTTPMiddleware


class CSRFMiddleware(BaseHTTPMiddleware):
    """
    CSRF protection using double-submit cookie pattern.

    Exempts:
    - GET/HEAD/OPTIONS requests
    - API endpoints under /v1/, /mcp/, /oauth/ (use Bearer tokens, not cookies)
    - Per-user MCP endpoints under /user-mcp/
    """

    SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
    EXEMPT_PREFIXES = (
        "/v1/",
        "/mcp/",
        "/oauth/",
        "/user-mcp/",
        "/static/",
        "/metrics",
        "/health",
        "/ready",
        "/live",
    )

    def __init__(self, app, secret_key: str, cookie_name: str = "csrf_token"):
        super().__init__(app)
        self.secret_key = secret_key.encode("utf-8")
        self.cookie_name = cookie_name

    def _generate_token(self) -> str:
        """Generate a CSRF token."""
        return secrets.token_urlsafe(32)

    def _verify_token(self, cookie_token: str, form_token: str) -> bool:
        """Verify that the form token matches the cookie token."""
        if not cookie_token or not form_token:
            return False
        return hmac.compare_digest(cookie_token, form_token)

    async def dispatch(self, request, call_next):
        method = request.method
        path = request.url.path

        # Skip safe methods
        if method in self.SAFE_METHODS:
            response = await call_next(request)
            # Set CSRF cookie on safe responses if not present
            cookie = request.cookies.get(self.cookie_name)
            if not cookie:
                response.set_cookie(
                    key=self.cookie_name,
                    value=self._generate_token(),
                    httponly=False,
                    samesite="lax",
                    secure=request.url.scheme == "https",
                )
            return response

        # Skip exempt paths (API endpoints use Bearer auth, not vulnerable to CSRF)
        if path.startswith(self.EXEMPT_PREFIXES):
            return await call_next(request)

        # For form POSTs, verify CSRF token
        cookie_token = request.cookies.get(self.cookie_name)

        # Try header first, then form field
        form_token = request.headers.get("X-CSRF-Token")
        if not form_token:
            try:
                form = await request.form()
                form_token = form.get("csrf_token")
            except Exception:
                pass

        if not self._verify_token(cookie_token or "", form_token or ""):
            from fastapi.responses import JSONResponse
            return JSONResponse(
                status_code=403,
                content={"error": "CSRF token validation failed"},
            )

        return await call_next(request)

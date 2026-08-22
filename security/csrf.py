"""
CSRF protection middleware for web UI forms.

Uses double-submit cookie pattern:
1. On GET requests, a CSRF token cookie is set
2. On POST/PUT/DELETE form requests, the token must be present
   in both the cookie and a hidden form field / header

Implementation note:
    This is written as pure ASGI middleware (not ``BaseHTTPMiddleware``)
    because form-field validation must read the request body.  Reading the
    body inside ``BaseHTTPMiddleware.dispatch`` exhausts the downstream
    receive channel, leaving handlers with an empty form.  Here we read the
    raw body once, validate, and hand the handler a *replayable* receive so
    the exact same bytes reach the route.
"""

from __future__ import annotations

import hmac
import secrets
from typing import Optional

from starlette.datastructures import MutableHeaders
from starlette.requests import Request
from starlette.responses import JSONResponse


class CSRFMiddleware:
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
        "/auth/login",
        "/auth/register",
        "/auth/me",
        "/auth/logout",
    )

    def __init__(self, app, secret_key: str, cookie_name: str = "csrf_token"):
        self.app = app
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

    # ------------------------------------------------------------------
    # ASGI entry point
    # ------------------------------------------------------------------

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive=receive)
        method = request.method.upper()
        path = request.url.path

        # Safe methods always pass; seed the CSRF cookie when missing.
        if method in self.SAFE_METHODS:
            if self.cookie_name in request.cookies:
                await self.app(scope, receive, send)
                return
            await self.app(scope, receive, self._cookie_seeding_send(request, send))
            return

        # Exempt paths (Bearer-token APIs are not vulnerable to CSRF).
        if path.startswith(self.EXEMPT_PREFIXES):
            await self.app(scope, receive, send)
            return

        cookie_token = request.cookies.get(self.cookie_name) or ""

        # Header first, then hidden form field.
        form_token: Optional[str] = request.headers.get("X-CSRF-Token")

        replay_receive = receive
        if not form_token:
            # Parse the form field WITHOUT losing the body: read the raw
            # bytes once, then replay them to the wrapped app below.
            body = await request.body()

            async def replay_receive() -> dict:  # noqa: F811 - intentional shadow
                return {"type": "http.request", "body": body, "more_body": False}

            try:
                form_request = Request(scope, receive=replay_receive)
                form = await form_request.form()
                value = form.get("csrf_token")
                form_token = value if isinstance(value, str) else None
            except Exception:
                form_token = None

        if not self._verify_token(cookie_token, form_token or ""):
            response = JSONResponse(
                status_code=403,
                content={"error": "CSRF token validation failed"},
            )
            await response(scope, receive, send)
            return

        await self.app(scope, replay_receive, send)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _cookie_seeding_send(self, request: Request, send):
        """Wrap ``send`` so the response carries a freshly seeded CSRF cookie."""
        secure = request.url.scheme == "https"
        cookie_parts = [
            f"{self.cookie_name}={self._generate_token()}",
            "Path=/",
            "SameSite=lax",
        ]
        if secure:
            cookie_parts.append("Secure")
        cookie_header = "; ".join(cookie_parts)

        async def wrapped_send(message):
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers.append("set-cookie", cookie_header)
            await send(message)

        return wrapped_send

"""
Tests for per-user MCP authentication modes (issue #6).

New behavior:
- POST /user-mcp/{connector}/mcp authenticates via the Authorization header
  (API keys never appear in URL paths)
- Legacy /user-mcp/{api_key}/{connector}/mcp is disabled unless
  RELAY_LEGACY_PATH_KEYS=1, and logs a deprecation warning when enabled

A stub ASGI app is mounted at /mcp/testconn exactly the way production
mounts connector MCP servers, so the forwarding bridge can be exercised
end-to-end (path rewrite, x-user-id injection) without the MCP SDK.
"""

import json

import pytest

from fastapi.testclient import TestClient


class StubConnectorMCP:
    """Minimal ASGI app standing in for a mounted connector MCP server."""

    def __init__(self):
        self.scopes = []
        self.bodies = []

    async def __call__(self, scope, receive, send):
        self.scopes.append(scope)
        body = b""
        while True:
            message = await receive()
            body += message.get("body", b"")
            if not message.get("more_body"):
                break
        self.bodies.append(body)
        from starlette.responses import JSONResponse
        response = JSONResponse({"jsonrpc": "2.0", "result": "stub-ok", "id": 1})
        await response(scope, receive, send)


@pytest.fixture
def env(monkeypatch):
    # Deterministic config; keep cookies insecure-allowed off (tests use https base_url)
    monkeypatch.setenv("RELAY_ALLOW_INSECURE_COOKIES", "true")
    yield monkeypatch


def _make_client():
    import gateway.server as server_module
    from auth.oauth import create_oauth_provider
    from auth.oauth_providers import create_oauth_provider as create_connector_oauth
    from backends.manager import BackendManager
    from connectors import ConnectorRegistry
    from security.middleware import (
        AuditLogger,
        InputValidator,
        IPRestrictions,
        RateLimiter,
        SecurityContext,
    )
    from config.settings import RelayConfig

    config = RelayConfig()
    audit = AuditLogger("/tmp/test_audit_user_mcp.log", enabled=False)
    server_module.state = server_module.AppState(
        config=config,
        oauth=create_oauth_provider("test-secret-key-usermcp"),
        connector_oauth=create_connector_oauth(config),
        security=SecurityContext(
            rate_limiter=RateLimiter(600, 10000),
            validator=InputValidator(),
            audit_logger=audit,
            ip_restrictions=IPRestrictions(),
        ),
        backends=BackendManager(),
        connectors=ConnectorRegistry(),
    )
    return TestClient(server_module.app, base_url="https://testserver", raise_server_exceptions=False)


def _register_and_get_key(client, username="mcpuser"):
    from auth import database as db
    db.init_db()
    r = client.post(
        "/auth/register", json={"username": username, "password": "test-password-123"}
    )
    assert r.status_code in (200, 409)
    r = client.post(
        "/auth/login", json={"username": username, "password": "test-password-123"}
    )
    assert r.status_code == 200
    r = client.post(
        "/v1/api-keys",
        json={"client_name": "mcp-client"},
    )
    assert r.status_code == 200, r.text
    return r.json()["api_key"], username


def _mounted_stub():
    """
    Mount a stub connector MCP app at /mcp/testconn.

    Starlette matches the FIRST matching route, so re-mounting the same path
    would leave earlier tests' stubs intercepting traffic. Instead, install
    the stub into an existing /mcp/testconn mount if one is present, else
    create the mount; either way, remove it afterwards so tests stay
    independent.
    """
    import gateway.server as server_module
    from starlette.routing import Mount

    for i, route in enumerate(server_module.app.routes):
        if isinstance(route, Mount) and route.path == "/mcp/testconn":
            stub = StubConnectorMCP()
            server_module.app.routes[i] = Mount("/mcp/testconn", app=stub)
            break
    else:
        stub = StubConnectorMCP()
        server_module.app.mount("/mcp/testconn", stub)

    return stub


@pytest.fixture(autouse=True)
def _cleanup_test_mounts():
    yield
    import gateway.server as server_module
    from starlette.routing import Mount
    server_module.app.routes[:] = [
        r for r in server_module.app.routes
        if not (isinstance(r, Mount) and r.path == "/mcp/testconn")
    ]


# -----------------------------------------------------------------------------
# Header-authenticated route (new default)
# -----------------------------------------------------------------------------

def test_header_route_forwards_with_bearer_key(env):
    client = _make_client()
    stub = _mounted_stub()
    api_key, username = _register_and_get_key(client)

    r = client.post(
        "/user-mcp/testconn/mcp",
        content=json.dumps({"jsonrpc": "2.0", "method": "tools/list", "id": 1}),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
    )
    assert r.status_code == 200, r.text
    assert r.json()["result"] == "stub-ok"
    assert len(stub.scopes) == 1
    assert stub.scopes[0]["path"] == "/mcp"

    from auth.database import get_user_by_username
    _user = get_user_by_username(username)
    assert _user is not None, f"user {username} missing"
    user_id = _user["id"]
    sent_headers = {k.decode().lower(): v.decode() for k, v in stub.scopes[0]["headers"]}
    assert sent_headers["x-user-id"] == user_id


def test_header_route_accepts_raw_key_without_bearer_prefix(env):
    client = _make_client()
    stub = _mounted_stub()
    api_key, _ = _register_and_get_key(client)

    r = client.post(
        "/user-mcp/testconn/mcp",
        content=b"{}",
        headers={"Authorization": api_key},
    )
    assert r.status_code == 200
    assert len(stub.bodies) == 1


def test_header_route_updates_last_used(env):
    client = _make_client()
    _mounted_stub()
    from auth.database import get_api_key
    api_key, _ = _register_and_get_key(client)
    assert get_api_key(api_key)["last_used_at"] is None

    client.post("/user-mcp/testconn/mcp", content=b"{}",
                headers={"Authorization": f"Bearer {api_key}"})
    assert get_api_key(api_key)["last_used_at"] is not None


def test_header_route_missing_authorization_rejected(env):
    client = _make_client()
    stub = _mounted_stub()
    r = client.post("/user-mcp/testconn/mcp", content=b"{}")
    assert r.status_code == 401
    assert "error" in r.json()
    assert len(stub.scopes) == 0


def test_header_route_rejects_non_relay_token(env):
    """OAuth-shaped tokens belong on /mcp/{connector}; do not accept them here."""
    client = _make_client()
    stub = _mounted_stub()
    r = client.post(
        "/user-mcp/testconn/mcp",
        content=b"{}",
        headers={"Authorization": "Bearer some-oauth-token"},
    )
    assert r.status_code == 401
    assert len(stub.scopes) == 0


def test_header_route_rejects_unknown_key(env):
    client = _make_client()
    stub = _mounted_stub()
    r = client.post(
        "/user-mcp/testconn/mcp",
        content=b"{}",
        headers={"Authorization": "Bearer relay_totally-invalid"},
    )
    assert r.status_code == 401
    assert len(stub.scopes) == 0


def test_header_route_unknown_connector_404(env):
    client = _make_client()
    api_key, _ = _register_and_get_key(client)
    r = client.post(
        "/user-mcp/nosuchconnector/mcp",
        content=b"{}",
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert r.status_code == 404
    assert "not mounted" in r.json()["error"]


def test_forwarded_response_sent_exactly_once(env):
    """Regression guard: the bridge must not emit a second ASGI response."""
    client = _make_client()
    _mounted_stub()
    api_key, _ = _register_and_get_key(client)
    r = client.post(
        "/user-mcp/testconn/mcp",
        content=b"{}",
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert r.status_code == 200
    assert r.json()["result"] == "stub-ok"


# -----------------------------------------------------------------------------
# Legacy path-key route (flag-gated, off by default)
# -----------------------------------------------------------------------------

def test_legacy_route_disabled_by_default(env):
    client = _make_client()
    stub = _mounted_stub()
    api_key, _ = _register_and_get_key(client)

    r = client.post(f"/user-mcp/{api_key}/testconn/mcp", content=b"{}")
    assert r.status_code == 404
    body = r.json()["error"]
    assert "RELAY_LEGACY_PATH_KEYS" in body
    assert "/user-mcp/{connector}/mcp" in body
    assert len(stub.scopes) == 0


def test_legacy_route_enabled_by_flag_forwards(env):
    env.setenv("RELAY_LEGACY_PATH_KEYS", "1")
    client = _make_client()
    stub = _mounted_stub()
    api_key, username = _register_and_get_key(client)

    r = client.post(f"/user-mcp/{api_key}/testconn/mcp", content=b"{}")
    assert r.status_code == 200, r.text
    assert r.json()["result"] == "stub-ok"
    assert stub.scopes[0]["path"] == "/mcp"

    from auth.database import get_user_by_username
    _user = get_user_by_username(username)
    assert _user is not None, f"user {username} missing"
    user_id = _user["id"]
    sent_headers = {k.decode().lower(): v.decode() for k, v in stub.scopes[0]["headers"]}
    assert sent_headers["x-user-id"] == user_id


def test_legacy_route_enabled_by_flag_accepts_true_yes(env):
    for value in ("true", "yes"):
        env.setenv("RELAY_LEGACY_PATH_KEYS", value)
        client = _make_client()
        _mounted_stub()
        api_key, _ = _register_and_get_key(client)
        r = client.post(f"/user-mcp/{api_key}/testconn/mcp", content=b"{}")
        assert r.status_code == 200, value
        env.delenv("RELAY_LEGACY_PATH_KEYS")


def test_legacy_route_bad_key_even_when_enabled(env):
    env.setenv("RELAY_LEGACY_PATH_KEYS", "1")
    client = _make_client()
    stub = _mounted_stub()
    _register_and_get_key(client)

    r = client.post("/user-mcp/relay_bogus/testconn/mcp", content=b"{}")
    assert r.status_code == 401
    assert len(stub.scopes) == 0


def test_legacy_route_logs_deprecation_warning_when_enabled(env, caplog):
    env.setenv("RELAY_LEGACY_PATH_KEYS", "1")
    client = _make_client()
    _mounted_stub()
    api_key, _ = _register_and_get_key(client)

    import logging
    with caplog.at_level(logging.WARNING, logger="gateway.server"):
        client.post(f"/user-mcp/{api_key}/testconn/mcp", content=b"{}")

    warnings = [rec for rec in caplog.records if "DEPRECATED" in rec.getMessage()]
    assert warnings, "expected a deprecation warning for path-key usage"


def test_disabled_legacy_route_does_not_log_deprecation(env, caplog):
    client = _make_client()
    _mounted_stub()

    import logging
    with caplog.at_level(logging.WARNING, logger="gateway.server"):
        client.post("/user-mcp/somekey/testconn/mcp", content=b"{}")

    assert not [rec for rec in caplog.records if "DEPRECATED" in rec.getMessage()]

"""
Tests for the deep readiness probe and production secure-cookie enforcement
(issue #13).

Covers:
- /ready returns 200 with per-check detail when everything is healthy
- /ready degrades to 503 naming the failing check when the SQLite database
  cannot be opened
- /ready degrades to 503 when Redis is configured but unreachable, and stays
  ready when Redis is simply not configured
- RELAY_ALLOW_INSECURE_COOKIES=true is rejected outright in production config
"""

import os

import pytest
from fastapi.testclient import TestClient


def _make_client():
    """Install a minimal AppState and return a test client + the state."""
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
    app_state = server_module.AppState(
        config=config,
        oauth=create_oauth_provider("test-secret-key-readiness"),
        connector_oauth=create_connector_oauth(config),
        security=SecurityContext(
            rate_limiter=RateLimiter(600, 10000),
            validator=InputValidator(),
            audit_logger=AuditLogger("/tmp/test_audit_readiness_disabled.log"),
            ip_restrictions=IPRestrictions(),
        ),
        backends=BackendManager(),
        connectors=ConnectorRegistry(),
    )
    previous_state = server_module.state
    server_module.state = app_state
    client = TestClient(server_module.app, base_url="https://testserver", raise_server_exceptions=False)
    return client, app_state, previous_state


@pytest.fixture()
def readiness_client():
    client, app_state, previous_state = _make_client()
    try:
        yield client, app_state
    finally:
        import gateway.server as server_module
        server_module.state = previous_state


# ===========================================================================
# /ready — happy path
# ===========================================================================

class TestReadinessHealthy:
    def test_ready_ok_when_no_backends_and_db_openable(self, readiness_client):
        client, _ = readiness_client
        resp = client.get("/ready")
        assert resp.status_code == 200
        body = resp.json()
        assert body["ready"] is True
        assert "degraded" not in body
        checks = body["checks"]
        assert checks["backends"]["ok"] is True
        assert checks["backends"]["total"] == 0
        assert checks["sqlite"]["ok"] is True
        # Redis not configured -> not applicable, must not fail readiness
        assert checks["redis"]["configured"] is False
        assert checks["redis"]["ok"] is True

    def test_live_still_shallow(self, readiness_client):
        client, _ = readiness_client
        resp = client.get("/live")
        assert resp.status_code == 200
        assert resp.json() == {"status": "alive"}


# ===========================================================================
# /ready — degradation paths
# ===========================================================================

class TestReadinessDegradation:
    def test_sqlite_unopenable_degrades_to_503(self, readiness_client, monkeypatch, tmp_path):
        from auth import database as auth_db

        client, _ = readiness_client
        # Point the auth DB resolver at a directory: sqlite3.connect() cannot
        # open it and raises sqlite3.OperationalError.
        unusable = tmp_path / "gateway.db"
        unusable.mkdir()
        monkeypatch.setattr(auth_db, "DB_PATH", str(unusable))

        resp = client.get("/ready")
        assert resp.status_code == 503
        body = resp.json()
        assert body["ready"] is False
        assert body["degraded"] == ["sqlite"]
        assert body["checks"]["sqlite"]["ok"] is False
        assert "error" in body["checks"]["sqlite"]
        # Unrelated checks stay green so operators can see exactly what broke
        assert body["checks"]["backends"]["ok"] is True
        assert body["checks"]["redis"]["ok"] is True

    def test_redis_configured_but_down_degrades_to_503(self, readiness_client):
        client, app_state = readiness_client
        # Port 1 on loopback: nothing listens, connection is refused promptly.
        app_state.config.database.redis_url = "redis://127.0.0.1:1/0"

        resp = client.get("/ready")
        assert resp.status_code == 503
        body = resp.json()
        assert body["ready"] is False
        assert body["degraded"] == ["redis"]
        assert body["checks"]["redis"]["configured"] is True
        assert body["checks"]["redis"]["ok"] is False
        assert "error" in body["checks"]["redis"]
        # SQLite itself remains healthy
        assert body["checks"]["sqlite"]["ok"] is True

    def test_backend_circuit_open_degrades_to_503(self, readiness_client):
        from backends.manager import BackendDefinition, BackendType, CircuitState

        client, app_state = readiness_client
        definition = BackendDefinition(
            id="readiness_probe_backend",
            name="readiness_probe_backend",
            description="readiness probe fixture",
            backend_type=BackendType.API_REST,
            tools=["readiness_probe_tool"],
        )
        app_state.backends.register_backend(definition)
        try:
            # Mark the backend as attempted, then force the circuit breaker
            # open so the backend is not ready. A never-attempted backend is
            # excluded from readiness entirely (tested below).
            state = app_state.backends.get_backend(definition.id)
            state.has_connected = True
            state.circuit_state = CircuitState.OPEN
            state.circuit_opened_at = None

            resp = client.get("/ready")
            assert resp.status_code == 503
            body = resp.json()
            assert body["ready"] is False
            assert "backends" in body["degraded"]
            assert body["checks"]["backends"]["circuit_open"] >= 1
        finally:
            app_state.backends.unregister_backend(definition.id)

    def test_never_connected_backends_do_not_degrade_readiness(self, readiness_client):
        """Optional backends without credentials/runtime stay DISCONNECTED and
        must not fail /ready — they are not backing services."""
        from backends.manager import BackendDefinition, BackendType

        client, app_state = readiness_client
        definition = BackendDefinition(
            id="optional_never_connected",
            name="optional_never_connected",
            description="never attempted optional integration",
            backend_type=BackendType.MCP_STDIO,
            tools=[],
        )
        app_state.backends.register_backend(definition)
        try:
            resp = client.get("/ready")
            assert resp.status_code == 200
            body = resp.json()
            assert body["ready"] is True
            checks = body["checks"]["backends"]
            assert checks["total"] == 1          # still visible for operators
            assert checks["attempted"] == 0      # but excluded from the gate
        finally:
            app_state.backends.unregister_backend(definition.id)


# ===========================================================================
# Production secure-cookie enforcement
# ===========================================================================

class TestSecureCookieEnforcement:
    def test_production_rejects_allow_insecure_cookies(self):
        from pydantic import ValidationError
        from config.settings import RelayConfig

        with pytest.raises(ValidationError) as excinfo:
            RelayConfig(environment="production", allow_insecure_cookies=True)
        assert "RELAY_ALLOW_INSECURE_COOKIES" in str(excinfo.value)

    def test_production_defaults_to_secure_cookies(self):
        from config.settings import RelayConfig

        config = RelayConfig(environment="production")
        assert config.allow_insecure_cookies is False

    def test_development_may_opt_out(self):
        import gateway.server as server_module
        from config.settings import RelayConfig

        config = RelayConfig(environment="development", allow_insecure_cookies=True)
        assert server_module._cookie_secure(config) is False

    def test_production_cookies_always_secure(self):
        import gateway.server as server_module
        from config.settings import RelayConfig

        config = RelayConfig(environment="production")
        assert server_module._cookie_secure(config) is True

    def test_prod_compose_pins_insecure_cookie_knob_off(self):
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        compose_path = os.path.join(repo_root, "docker-compose.prod.yml")
        with open(compose_path, "r") as fh:
            compose_text = fh.read()
        assert 'RELAY_ALLOW_INSECURE_COOKIES: "false"' in compose_text
        assert "RELAY_ENVIRONMENT: production" in compose_text

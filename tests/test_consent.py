"""
Tests for the OAuth consent screen (issues #2 / #11).

- Unauthenticated authorize requests redirect to login
- Consent screen is bound to the authenticated session and shows
  client + requested scopes
- Approve/deny decisions persist; denial prevents code issuance
- Audit entries carry the real authenticated user id and client_id
- Consent form posts require a CSRF token
"""

import json

import pytest
from fastapi.testclient import TestClient


AUTHORIZE_PARAMS = {
    "client_id": "",
    "redirect_uri": "http://localhost/cb",
    "code_challenge": "consent-test-challenge",
    "code_challenge_method": "S256",
    "scope": "mcp:tools",
}


def _make_client(audit_path=None):
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
    audit = AuditLogger(
        audit_path or "/tmp/test_audit_consent_disabled.log",
        enabled=bool(audit_path),
    )
    server_module.state = server_module.AppState(
        config=config,
        oauth=create_oauth_provider("test-secret-key-consent"),
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
    return TestClient(server_module.app, raise_server_exceptions=False)


def _register_and_login(client, username):
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
    return r.json()


def _register_client(client, name="consent-app"):
    resp = client.post(
        "/oauth/register",
        json={"client_name": name, "redirect_uris": ["http://localhost/cb"]},
    )
    assert resp.status_code == 200
    return resp.json()["client_id"]


def _consent_post(client, cid, decision, csrf_token=None, **overrides):
    data = dict(AUTHORIZE_PARAMS)
    data["client_id"] = cid
    data["decision"] = decision
    data["csrf_token"] = csrf_token if csrf_token is not None else client.cookies.get("csrf_token")
    data.update(overrides)
    return client.post("/oauth/authorize/consent", data=data, follow_redirects=False)


class TestConsentFlow:
    def test_unauthenticated_authorize_redirects_to_login(self):
        client = _make_client()
        cid = _register_client(client)
        params = dict(AUTHORIZE_PARAMS)
        params["client_id"] = cid
        resp = client.get("/oauth/authorize", params=params, follow_redirects=False)
        assert resp.status_code in (302, 303, 307)
        assert "/auth/login" in resp.headers["location"]

    def test_unauthenticated_consent_post_rejected(self):
        client = _make_client()
        cid = _register_client(client)
        resp = _consent_post(client, cid, "approve", csrf_token="whatever")
        assert resp.status_code == 401

    def test_consent_screen_renders_for_session_user(self):
        client = _make_client()
        user = _register_and_login(client, "consent_viewer")
        cid = _register_client(client, "visible-app")
        params = dict(AUTHORIZE_PARAMS)
        params["client_id"] = cid
        resp = client.get("/oauth/authorize", params=params)
        assert resp.status_code == 200
        html = resp.text
        assert "visible-app" in html
        assert "mcp:tools" in html
        assert user["username"] in html
        # Approve/deny buttons present
        assert 'value="approve"' in html
        assert 'value="deny"' in html

    def test_denied_consent_prevents_code_issuance(self):
        client = _make_client()
        _register_and_login(client, "consent_denier")
        cid = _register_client(client)

        # Fetch consent page (sets CSRF cookie), then deny
        params = dict(AUTHORIZE_PARAMS)
        params["client_id"] = cid
        client.get("/oauth/authorize", params=params)
        resp = _consent_post(client, cid, "deny")
        assert resp.status_code == 303
        assert "error=access_denied" in resp.headers["location"]

        # A subsequent authorize attempt must NOT issue a code
        params = dict(AUTHORIZE_PARAMS)
        params["client_id"] = cid
        second = client.get("/oauth/authorize", params=params, follow_redirects=False)
        assert second.status_code in (302, 303, 307)
        assert "error=access_denied" in second.headers["location"]
        assert "code=" not in second.headers["location"]

        # Token exchange with any code must fail (no code was ever issued)
        token_resp = client.post(
            "/oauth/token",
            json={
                "grant_type": "authorization_code",
                "code": "fabricated-code",
                "code_verifier": "x",
                "client_id": cid,
                "redirect_uri": "http://localhost/cb",
            },
        )
        assert token_resp.status_code == 400

    def test_approved_consent_issues_code_and_persists_decision(self):
        from auth.database import get_oauth_consent

        client = _make_client()
        user = _register_and_login(client, "consent_approver")
        cid = _register_client(client)

        params = dict(AUTHORIZE_PARAMS)
        params["client_id"] = cid
        client.get("/oauth/authorize", params=params)
        resp = _consent_post(client, cid, "approve")
        assert resp.status_code == 303
        location = resp.headers["location"]
        assert location.startswith("http://localhost/cb?code="), location

        # Decision persisted for the real user id
        consent = get_oauth_consent(user["user_id"], cid, "mcp:tools")
        assert consent is not None
        assert consent["decision"] == "approved"

        # Stored approval short-circuits the UI on the next authorize
        params = dict(AUTHORIZE_PARAMS)
        params["client_id"] = cid
        second = client.get("/oauth/authorize", params=params, follow_redirects=False)
        assert second.status_code in (302, 303, 307)
        assert "code=" in second.headers["location"]

    def test_consent_form_requires_csrf_token(self):
        client = _make_client()
        _register_and_login(client, "csrf_victim")
        cid = _register_client(client)

        missing = _consent_post(client, cid, "approve", csrf_token="")
        assert missing.status_code == 403

        wrong = _consent_post(client, cid, "approve", csrf_token="forged-token")
        assert wrong.status_code == 403


class TestConsentAudit:
    def test_audit_uses_real_user_id_and_client_id(self, tmp_path):
        audit_path = tmp_path / "audit.log"
        client = _make_client(str(audit_path))
        user = _register_and_login(client, "audit_user")
        cid = _register_client(client, "audited-app")

        params = dict(AUTHORIZE_PARAMS)
        params["client_id"] = cid
        client.get("/oauth/authorize", params=params)
        resp = _consent_post(client, cid, "approve")
        assert resp.status_code == 303

        events = [json.loads(line) for line in audit_path.read_text().splitlines()]
        consent_events = [
            e for e in events if e["event_type"] in ("oauth_authorize", "oauth_consent_denied")
        ]
        assert consent_events, f"no oauth audit events found: {events}"
        for event in consent_events:
            assert event["user_id"] == user["user_id"]
            assert event["client_id"].startswith("client_")
        assert not any(e["user_id"] == "demo_user" for e in events)

"""
Tests for API key lifecycle (issue #1).

- POST /v1/api-keys requires an authenticated principal
- Keys carry owner metadata; listing scoped to owner unless admin
- Minted keys authenticate against /v1/* endpoints
"""

import pytest

from fastapi.testclient import TestClient


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
    audit = AuditLogger("/tmp/test_audit_apikeys.log", enabled=False)
    server_module.state = server_module.AppState(
        config=config,
        oauth=create_oauth_provider("test-secret-key-apikeys"),
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


class TestApiKeyCreationAuth:
    def test_unauthenticated_creation_returns_401(self):
        client = _make_client()
        resp = client.post("/v1/api-keys", json={"client_name": "cli"})
        assert resp.status_code == 401

    def test_session_authenticated_creation_succeeds_with_owner(self):
        client = _make_client()
        user = _register_and_login(client, "key_owner_a")
        resp = client.post("/v1/api-keys", json={"client_name": "my-cli"})
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["api_key"].startswith("relay_")
        assert body["owner"]["user_id"] == user["user_id"]
        assert body["owner"]["auth_method"] == "session"

    def test_bearer_token_authenticated_creation(self):
        client = _make_client()
        _register_and_login(client, "key_owner_b")
        # Mint a key via session, then use it as Bearer to mint another
        first = client.post("/v1/api-keys", json={"client_name": "bootstrap"})
        assert first.status_code == 200
        key = first.json()["api_key"]

        second = client.post(
            "/v1/api-keys",
            json={"client_name": "via-key"},
            headers={"Authorization": f"Bearer {key}"},
        )
        assert second.status_code == 200, second.text
        owner = second.json()["owner"]
        assert owner["auth_method"] == "api_key"

    def test_invalid_bearer_returns_401(self):
        client = _make_client()
        resp = client.post(
            "/v1/api-keys",
            json={"client_name": "x"},
            headers={"Authorization": "Bearer relay_notarealkey12345"},
        )
        assert resp.status_code == 401


class TestApiKeyListing:
    def test_listing_scoped_to_owner(self):
        client = _make_client()
        user_a = _register_and_login(client, "list_owner_a")
        client.post("/v1/api-keys", json={"client_name": "a-key"})

        other = _make_client()
        _register_and_login(other, "list_owner_b")
        other.post("/v1/api-keys", json={"client_name": "b-key"})

        resp = client.get("/v1/api-keys")
        assert resp.status_code == 200
        keys = resp.json()["keys"]
        assert keys, "expected at least one key"
        assert all(k["user_id"] == user_a["user_id"] for k in keys)

    def test_listing_masks_full_key(self):
        client = _make_client()
        _register_and_login(client, "mask_owner")
        created = client.post("/v1/api-keys", json={"client_name": "m"}).json()
        listed = client.get("/v1/api-keys").json()["keys"]
        assert all(k["key_prefix"] != created["api_key"] for k in listed)


class TestMintedKeyUsableOnV1:
    def test_minted_key_authenticates_v1_tokens_endpoint(self):
        client = _make_client()
        _register_and_login(client, "usable_key_owner")
        key = client.post("/v1/api-keys", json={"client_name": "use-me"}).json()["api_key"]

        resp = client.get("/v1/tokens", headers={"Authorization": f"Bearer {key}"})
        assert resp.status_code == 200, resp.text
        assert resp.json()["user_id"].startswith("usr_")

    def test_revoked_key_rejected(self):
        from auth import database as db

        client = _make_client()
        user = _register_and_login(client, "revoke_owner")
        key = client.post("/v1/api-keys", json={"client_name": "short-lived"}).json()["api_key"]

        assert db.delete_api_key(user["user_id"], key) is True
        resp = client.get("/v1/tokens", headers={"Authorization": f"Bearer {key}"})
        assert resp.status_code == 401

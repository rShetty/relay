"""
Tests for the full API-key lifecycle (issue #17).

Complements tests/test_api_keys.py (creation auth + listing) with:
- Key format and per-user uniqueness
- Expiry: expires_days honoured, expired keys rejected at auth time
- last_used_at updated on authenticated use
- Ownership: a user cannot delete another user's key
- DB-level create/get/list/delete round-trip
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
    audit = AuditLogger("/tmp/test_audit_keylifecycle.log", enabled=False)
    server_module.state = server_module.AppState(
        config=config,
        oauth=create_oauth_provider("test-secret-key-lifecycle"),
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


def _mint(client, name="lifecycle-key", expires_days=None):
    payload = {"client_name": name}
    if expires_days is not None:
        payload["expires_days"] = expires_days
    resp = client.post("/v1/api-keys", json=payload)
    assert resp.status_code == 200, resp.text
    return resp.json()


class TestKeyCreation:
    def test_key_format_and_owner_metadata(self):
        client = _make_client()
        user = _register_and_login(client, "lifecycle_owner_a")
        body = _mint(client, name="ci-key")
        assert body["api_key"].startswith("relay_")
        assert len(body["api_key"]) > 40  # relay_ + 32-byte urlsafe token
        assert body["owner"]["user_id"] == user["user_id"]
        assert body["owner"]["auth_method"] == "session"
        assert body["client_name"] == "ci-key"

    def test_keys_are_unique_per_mint(self):
        client = _make_client()
        _register_and_login(client, "lifecycle_owner_b")
        k1 = _mint(client)["api_key"]
        k2 = _mint(client)["api_key"]
        assert k1 != k2

    def test_listing_reports_name_and_masked_prefix(self):
        client = _make_client()
        user = _register_and_login(client, "lifecycle_owner_c")
        minted = _mint(client, name="named-key")["api_key"]
        listed = client.get("/v1/api-keys").json()["keys"]
        entry = next(k for k in listed if k["user_id"] == user["user_id"])
        assert entry["name"] == "named-key"
        assert entry["key_prefix"].endswith("...")
        assert minted not in entry["key_prefix"]


class TestKeyExpiry:
    def test_expired_key_rejected_on_use(self):
        client = _make_client()
        _register_and_login(client, "lifecycle_expiry_user")
        key = _mint(client, expires_days=-1)["api_key"]  # already expired
        resp = client.get("/v1/tokens", headers={"Authorization": f"Bearer {key}"})
        assert resp.status_code == 401

    def test_non_expired_key_accepted(self):
        client = _make_client()
        _register_and_login(client, "lifecycle_expiry_user2")
        key = _mint(client, expires_days=30)["api_key"]
        resp = client.get("/v1/tokens", headers={"Authorization": f"Bearer {key}"})
        assert resp.status_code == 200, resp.text

    def test_get_api_key_returns_none_for_expired(self):
        from auth import database as db

        client = _make_client()
        user = _register_and_login(client, "lifecycle_expiry_user3")
        key = _mint(client, expires_days=-1)["api_key"]
        assert db.get_api_key(key) is None
        assert db.get_api_key("relay_does_not_exist") is None
        assert user["user_id"]  # user exists for sanity


class TestLastUsedTracking:
    def test_last_used_at_updated_on_authenticated_use(self):
        from auth import database as db

        client = _make_client()
        _register_and_login(client, "lifecycle_lastused_user")
        key = _mint(client)["api_key"]

        before = next(
            k for k in db.list_api_keys(_current_user_id(client)) if k["key"] == key
        )["last_used_at"]
        assert before is None

        resp = client.get("/v1/tokens", headers={"Authorization": f"Bearer {key}"})
        assert resp.status_code == 200

        after = next(
            k for k in db.list_api_keys(_current_user_id(client)) if k["key"] == key
        )["last_used_at"]
        assert after is not None


def _current_user_id(client):
    """Resolve the logged-in user's id from the session (or DB fallback)."""
    from auth import database as db

    me = client.get("/auth/me")
    if me.status_code == 200:
        return me.json()["id"]
    row = db.get_user_by_username("lifecycle_lastused_user")
    if row is None:
        raise RuntimeError("lifecycle user missing from database")
    return row["id"]


class TestKeyDeletion:
    def test_owner_can_delete_own_key(self):
        from auth import database as db

        client = _make_client()
        user = _register_and_login(client, "lifecycle_delete_owner")
        key = _mint(client)["api_key"]
        assert db.delete_api_key(user["user_id"], key) is True
        # Key no longer authenticates
        resp = client.get("/v1/tokens", headers={"Authorization": f"Bearer {key}"})
        assert resp.status_code == 401

    def test_cannot_delete_another_users_key(self):
        from auth import database as db

        client_a = _make_client()
        user_a = _register_and_login(client_a, "lifecycle_del_user_a")
        key_a = _mint(client_a)["api_key"]

        client_b = _make_client()
        user_b = _register_and_login(client_b, "lifecycle_del_user_b")
        _mint(client_b)

        # user_b cannot delete user_a's key (ownership check in WHERE clause)
        assert db.delete_api_key(user_b["user_id"], key_a) is False
        # user_a's key still works
        resp = client_a.get("/v1/tokens", headers={"Authorization": f"Bearer {key_a}"})
        assert resp.status_code == 200
        assert user_a["user_id"]


class TestDBLevelLifecycle:
    def test_create_get_list_delete_roundtrip(self):
        from auth import database as db

        client = _make_client()
        user = _register_and_login(client, "lifecycle_db_user")
        uid = user["user_id"]

        key = db.create_api_key(uid, "db-level-key")
        assert key.startswith("relay_")

        data = db.get_api_key(key)
        assert data is not None
        assert data["user_id"] == uid
        assert data["name"] == "db-level-key"
        assert data["is_active"] == 1

        listed = db.list_api_keys(uid)
        assert any(k["key"] == key for k in listed)

        db.update_api_key_last_used(key)
        assert db.get_api_key(key)["last_used_at"] is not None

        assert db.delete_api_key(uid, key) is True
        assert db.get_api_key(key) is None

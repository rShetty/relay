"""
Tests for the result-DLP hook (issue #17).

Unit level:
- Sensitive key redaction (token/password/api_key/... at any nesting depth)
- Value-pattern redaction for known credential formats in free text
- Pass-through behaviour for benign data; disabled inspector is a no-op

Integration level:
- ``gateway.server._execute_tool`` scrubs a secret echoed back by a stubbed
  backend before returning to the caller
- Disabling DLP via SecurityContext lets the secret through
"""

import json

import pytest
from fastapi.testclient import TestClient

from security.dlp import (
    ResultDLPInspector,
    get_dlp_inspector,
    set_dlp_inspector,
)


@pytest.fixture(autouse=True)
def _restore_default_inspector():
    """Keep process-wide inspector state isolated between tests."""
    yield
    set_dlp_inspector(None)


class TestSensitiveKeys:
    def setup_method(self):
        self.dlp = ResultDLPInspector()

    def test_top_level_sensitive_key_redacted(self):
        out = self.dlp.inspect_result({"access_token": "supersecret123"})
        assert out == {"access_token": "[REDACTED]"}

    def test_nested_sensitive_keys_redacted(self):
        # NOTE: "credentials" is itself a sensitive key name, so the entire
        # subtree under it is conservatively collapsed to [REDACTED].
        result = {
            "user": {
                "name": "alice",
                "credentials": {"password": "hunter2", "api_key": "sk-abcdef1234567890"},
            },
            "session_id": "abc123",
            "profile": {"bio_token_count": 5},
        }
        out = self.dlp.inspect_result(result)
        assert out["user"]["name"] == "alice"
        assert out["user"]["credentials"] == "[REDACTED]"
        assert out["session_id"] == "[REDACTED]"
        # Key matching is case-insensitive SUBSTRING based (fail-closed): any
        # key merely containing e.g. "token" is redacted even when its value
        # is innocuous.  Over-redaction is preferred over any leak risk.
        assert out["profile"]["bio_token_count"] == "[REDACTED]"

    def test_benign_data_untouched(self):
        result = {
            "id": 42,
            "title": "Fix login bug",
            "tags": ["bug", "auth"],
            "score": 3.14,
            "active": True,
        }
        assert self.dlp.inspect_result(result) == result

    def test_key_match_is_substring_case_insensitive(self):
        # e.g. GitHub-style payloads: "access_token", "refreshToken", "PAT"
        out = self.dlp.inspect_result(
            {"refreshToken": "xyz", "X-Api-Key": "xyz2", "PRIVATE_KEY": "pem"}
        )
        assert all(v == "[REDACTED]" for v in out.values())

    def test_lists_and_tuples_walked(self):
        out = self.dlp.inspect_result([{"token": "t1"}, {"note": "clean"}])
        assert out[0]["token"] == "[REDACTED]"
        assert out[1] == {"note": "clean"}


class TestValuePatterns:
    def setup_method(self):
        self.dlp = ResultDLPInspector()

    def test_relay_api_key_in_text(self):
        text = "Your key relay_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456 is invalid"
        out = self.dlp.inspect_result({"message": text})
        assert "relay_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456" not in out["message"]
        assert "[REDACTED]" in out["message"]

    def test_github_pat_in_error_message(self):
        text = "auth failed for ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
        out = self.dlp.inspect_result(text)
        assert "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8" not in out

    def test_jwt_redacted(self):
        jwt = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        out = self.dlp.inspect_result({"detail": f"Bearer {jwt} rejected"})
        assert jwt not in out["detail"]

    def test_slack_token_redacted(self):
        token = "xoxb-REDACTED-TEST-FIXTURE-abcdefghijklmnop"
        out = self.dlp.inspect_result({"text": f"using {token}"})
        assert token not in out["text"]

    def test_aws_access_key_redacted(self):
        out = self.dlp.inspect_result("key AKIAIOSFODNN7EXAMPLE leaked")
        assert "AKIAIOSFODNN7EXAMPLE" not in out

    def test_plain_strings_not_matching_patterns_pass_through(self):
        assert self.dlp.inspect_result("just an ordinary message") == "just an ordinary message"


class TestDisabledAndDefaults:
    def test_disabled_inspector_is_noop(self):
        dlp = ResultDLPInspector(enabled=False)
        secret = {"password": "hunter2"}
        assert dlp.inspect_result(secret) == secret

    def test_process_wide_default_available(self):
        inspector = get_dlp_inspector()
        assert isinstance(inspector, ResultDLPInspector)

    def test_set_none_disables_hook(self):
        set_dlp_inspector(None)
        from security.dlp import inspect_tool_result

        secret = {"token": "keep-me"}
        assert inspect_tool_result(secret) == secret


# -----------------------------------------------------------------------------
# Integration with gateway._execute_tool
# -----------------------------------------------------------------------------

def _make_client(dlp_enabled=True, backend_result=None):
    import gateway.server as server_module
    from auth.oauth import create_oauth_provider
    from auth.oauth_providers import create_oauth_provider as create_connector_oauth
    from backends.manager import BackendDefinition, BackendManager, BackendType
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
    audit = AuditLogger("/tmp/test_audit_dlp.log", enabled=False)

    defn = BackendDefinition(
        id="leaky_backend",
        name="Leaky Backend",
        description="echoes credentials",
        backend_type=BackendType.API_REST,
        tools=["leak_tool"],
    )
    backends = BackendManager()
    backends.register_backend(defn)
    backends._tool_index["leak_tool"] = "leaky_backend"

    async def _stub_call(*args, **kwargs):
        return True, backend_result

    backends.call_tool = _stub_call

    server_module.state = server_module.AppState(
        config=config,
        oauth=create_oauth_provider("test-secret-key-dlp"),
        connector_oauth=create_connector_oauth(config),
        security=SecurityContext(
            rate_limiter=RateLimiter(600, 10000),
            validator=InputValidator(),
            audit_logger=audit,
            ip_restrictions=IPRestrictions(),
            dlp_inspector=ResultDLPInspector(enabled=dlp_enabled),
        ),
        backends=backends,
        connectors=ConnectorRegistry(),
    )
    return TestClient(server_module.app, base_url="https://testserver", raise_server_exceptions=False)


def _mint_key(client, username):
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
    return client.post("/v1/api-keys", json={"client_name": "dlp-test"}).json()["api_key"]


LEAKING_RESULT = {
    "message": "Authentication failed for token relay_QWERTYUIOPASDFGHJKLZXCVBNM12345",
    "account": {"name": "svc-account", "api_key": "sk-live-abcdefgh1234567890"},
}


class TestExecuteToolDLPIntegration:
    # TestClient presents peer host "testclient", which IPRestrictions fails
    # closed on. Exercise the real TRUSTED_PROXY path instead: with the env
    # var set, the gateway takes the client IP from X-Forwarded-For.
    @pytest.fixture(autouse=True)
    def _trusted_proxy(self, monkeypatch):
        monkeypatch.setenv("TRUSTED_PROXY", "1")
        yield

    def _call(self, client, key):
        return client.post(
            "/v1/call",
            json={"tool_name": "leak_tool", "arguments": {}},
            headers={
                "Authorization": f"Bearer {key}",
                "X-Forwarded-For": "203.0.113.7",
            },
        )

    def test_secrets_scrubbed_from_v1_call_result(self):
        client = _make_client(dlp_enabled=True, backend_result=LEAKING_RESULT)
        key = _mint_key(client, "dlp_user_a")
        resp = self._call(client, key)
        assert resp.status_code == 200, resp.text
        result = resp.json()["result"]
        assert "relay_QWERTYUIOPASDFGHJKLZXCVBNM12345" not in json.dumps(result)
        assert result["message"].endswith("[REDACTED]")
        assert result["account"]["api_key"] == "[REDACTED]"
        assert result["account"]["name"] == "svc-account"

    def test_dlp_can_be_disabled_via_security_context(self):
        client = _make_client(dlp_enabled=False, backend_result=LEAKING_RESULT)
        key = _mint_key(client, "dlp_user_b")
        resp = self._call(client, key)
        assert resp.status_code == 200, resp.text
        result = resp.json()["result"]
        # With DLP off the raw secret passes through untouched.
        assert result["message"].endswith("relay_QWERTYUIOPASDFGHJKLZXCVBNM12345")

"""
Tests for SSRF validation of admin-installed backend URLs (issue #4).

All DNS resolution is mocked so no real network calls happen.
"""

import ipaddress
import socket

import pytest
from fastapi.testclient import TestClient

from security.ssrf import (
    METADATA_IP,
    is_blocked_ip,
    is_loopback_host,
    validate_backend_url,
)


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

def _mock_resolution(monkeypatch, ips):
    """Patch socket.getaddrinfo to return *ips* for every hostname."""
    def fake_getaddrinfo(host, port, *args, **kwargs):
        results = []
        for ip_str in ips:
            addr = ipaddress.ip_address(ip_str)
            family = socket.AF_INET6 if addr.version == 6 else socket.AF_INET
            results.append((family, socket.SOCK_STREAM, 6, "", (ip_str, port or 443)))
        return results

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)


def _mock_resolution_failure(monkeypatch):
    def fake_getaddrinfo(host, port, *args, **kwargs):
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)


# -----------------------------------------------------------------------------
# Unit tests: validate_backend_url
# -----------------------------------------------------------------------------

class TestSchemeValidation:
    def test_https_public_host_accepted(self, monkeypatch):
        _mock_resolution(monkeypatch, ["93.184.216.34"])
        ok, reason = validate_backend_url("https://api.example.com/mcp")
        assert ok, reason
        assert reason == ""

    def test_non_https_rejected(self, monkeypatch):
        _mock_resolution(monkeypatch, ["93.184.216.34"])
        ok, reason = validate_backend_url("http://api.example.com/mcp")
        assert not ok
        assert "https" in reason

    def test_unknown_scheme_rejected(self):
        ok, reason = validate_backend_url("ftp://api.example.com/pub")
        assert not ok
        assert "https" in reason

    def test_missing_scheme_rejected(self):
        ok, reason = validate_backend_url("api.example.com/mcp")
        assert not ok

    def test_empty_url_rejected(self):
        ok, reason = validate_backend_url("")
        assert not ok


class TestLoopbackException:
    def test_http_loopback_hostname_allowed(self):
        ok, reason = validate_backend_url("http://localhost:8080/mcp")
        assert ok, reason

    def test_http_loopback_ip_literal_allowed(self):
        ok, reason = validate_backend_url("http://127.0.0.1:9900")
        assert ok, reason

    def test_http_private_host_rejected(self, monkeypatch):
        # http is only allowed for loopback, not for any internal host
        ok, reason = validate_backend_url("http://10.0.0.5:8000")
        assert not ok
        assert "https" in reason

    def test_is_loopback_host(self):
        assert is_loopback_host("localhost")
        assert is_loopback_host("127.0.0.1")
        assert is_loopback_host("::1")
        assert not is_loopback_host("api.example.com")
        assert not is_loopback_host("10.0.0.1")


class TestBlockedIps:
    @pytest.mark.parametrize(
        "url",
        [
            "https://10.0.0.7/v1",                # 10/8
            "https://172.16.0.9/api",             # 172.16/12
            "https://192.168.1.20",               # 192.168/16
            "https://127.0.0.2:8443",             # 127/8
            f"https://{METADATA_IP}/latest/meta-data/",  # metadata svc
            "https://0.0.0.0",
        ],
    )
    def test_private_and_metadata_literals_rejected(self, url):
        ok, reason = validate_backend_url(url)
        assert not ok
        assert "blocked" in reason.lower()

    def test_metadata_resolved_hostname_rejected(self, monkeypatch):
        _mock_resolution(monkeypatch, ["169.254.169.254"])
        ok, reason = validate_backend_url("https://metadata.internal.example")
        assert not ok
        assert "169.254.169.254" in reason

    def test_private_resolved_hostname_rejected(self, monkeypatch):
        _mock_resolution(monkeypatch, ["10.0.0.42"])
        ok, reason = validate_backend_url("https://internal.example.com")
        assert not ok
        assert "10.0.0.42" in reason

    def test_any_blocked_record_rejects(self, monkeypatch):
        # Multi-record host: one bad address must be enough to reject.
        _mock_resolution(monkeypatch, ["93.184.216.34", "192.168.0.10"])
        ok, reason = validate_backend_url("https://mixed.example.com")
        assert not ok
        assert "192.168.0.10" in reason

    def test_ipv6_loopback_literal_rejected(self):
        ok, reason = validate_backend_url("https://[::1]:8443")
        assert not ok
        assert "blocked" in reason.lower()

    def test_unresolvable_host_rejected(self, monkeypatch):
        _mock_resolution_failure(monkeypatch)
        ok, reason = validate_backend_url("https://does-not-exist.example.com")
        assert not ok
        assert "resolve" in reason.lower()

    def test_is_blocked_ip_variants(self):
        assert is_blocked_ip(ipaddress.ip_address("10.1.2.3"))
        assert is_blocked_ip(ipaddress.ip_address("172.31.255.1"))
        assert is_blocked_ip(ipaddress.ip_address("192.168.0.1"))
        assert is_blocked_ip(ipaddress.ip_address("127.0.0.1"))
        assert is_blocked_ip(ipaddress.ip_address("169.254.169.254"))
        assert is_blocked_ip(ipaddress.ip_address("fe80::1"))
        assert is_blocked_ip(ipaddress.ip_address("fc00::1"))
        assert is_blocked_ip(ipaddress.ip_address("::1"))
        assert is_blocked_ip(ipaddress.ip_address("::ffff:10.0.0.1"))  # v4-mapped
        assert not is_blocked_ip(ipaddress.ip_address("93.184.216.34"))
        assert not is_blocked_ip(ipaddress.ip_address("2606:2800:220:1:248:1893:25c8:1946"))


# -----------------------------------------------------------------------------
# Integration test: /admin/backends/install endpoint
# -----------------------------------------------------------------------------

def _make_admin_client():
    import gateway.server as server_module
    from auth import database as db
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
    audit = AuditLogger("/tmp/test_audit_ssrf_disabled.log", enabled=False)
    server_module.state = server_module.AppState(
        config=config,
        oauth=create_oauth_provider("test-secret-key-ssrf"),
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

    db.init_db()
    client = TestClient(server_module.app, base_url="https://testserver", raise_server_exceptions=False)

    r = client.post(
        "/auth/register", json={"username": "ssrf_admin", "password": "test-password-123"}
    )
    assert r.status_code in (200, 409)
    r = client.post(
        "/auth/login", json={"username": "ssrf_admin", "password": "test-password-123"}
    )
    assert r.status_code == 200
    user_id = r.json()["user_id"]
    assert db.set_user_admin(user_id, True)
    return client


def _install_payload(url):
    return {
        "backend_id": "backend-ssrf-test",
        "backend_name": "SSRF Test Backend",
        "backend_type": "mcp_http",
        "client_id": "cid",
        "client_secret": "csecret",
        "config": {"url": url},
    }


def _csrf_post(client, path, payload):
    """POST *payload* with the CSRF double-submit header the middleware expects.

    A prior GET seeds the csrf_token cookie; /admin/* is not CSRF-exempt.
    """
    if not client.cookies.get("csrf_token"):
        client.get("/health")
    token = client.cookies.get("csrf_token")
    assert token, "expected a CSRF cookie after a safe request"
    return client.post(path, json=payload, headers={"X-CSRF-Token": token})


def _error_message(resp):
    """Error bodies use {"error": ...} (global handler), fall back to detail."""
    body = resp.json()
    return body.get("error") or body.get("detail") or ""


class TestInstallEndpointSsrfValidation:
    # One client for the whole class: the app's DB helpers leave connections
    # open, so repeated init_db/register cycles per test trip SQLite locks.
    client = None

    @classmethod
    def setup_class(cls):
        cls.client = _make_admin_client()

    def test_install_rejects_metadata_url(self):
        resp = _csrf_post(self.client, "/admin/backends/install", _install_payload(
            "https://169.254.169.254/latest/meta-data/"
        ))
        assert resp.status_code == 400
        assert "SSRF" in _error_message(resp)

    def test_install_rejects_private_resolving_url(self, monkeypatch):
        _mock_resolution(monkeypatch, ["10.0.0.7"])
        resp = _csrf_post(self.client, "/admin/backends/install", _install_payload(
            "https://internal.example.com"
        ))
        assert resp.status_code == 400
        assert "SSRF" in _error_message(resp)

    def test_install_rejects_non_https_url(self):
        resp = _csrf_post(self.client, "/admin/backends/install", _install_payload(
            "http://api.example.com/mcp"
        ))
        assert resp.status_code == 400
        assert "SSRF" in _error_message(resp)

    def test_install_accepts_public_https_url(self, monkeypatch):
        _mock_resolution(monkeypatch, ["93.184.216.34"])

        # Avoid a real network connection attempt to the mocked public host.
        from backends.manager import BackendManager

        async def fake_connect(self, backend_id):
            return True, None

        monkeypatch.setattr(BackendManager, "connect_backend", fake_connect)

        resp = _csrf_post(self.client, "/admin/backends/install", _install_payload(
            "https://api.example.com/mcp"
        ))
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["backend_id"] == "backend-ssrf-test"
        assert body["status"] == "connected"

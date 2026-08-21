"""
Tests for CSRFMiddleware (issue #17).

Uses a minimal in-process ASGI app that mirrors the gateway's route layout:
- Exempt prefixes (/v1/, /mcp/, /oauth/, ...) accept cookie-less POSTs
  (Bearer-token APIs are not CSRF-vulnerable)
- Non-exempt form POSTs require the double-submit token
  (cookie value == X-CSRF-Token header / csrf_token form field)
- Safe methods always pass and seed the CSRF cookie when missing
"""

import pytest
from starlette.applications import Starlette
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.testclient import TestClient

from security.csrf import CSRFMiddleware


SECRET = "csrf-test-secret-key"


def _build_app():
    async def ok(request):
        return PlainTextResponse("ok")

    async def echo_form(request):
        form = await request.form()
        return JSONResponse({"posted": dict(form)})

    routes = [
        ("/form/submit", echo_form, ["POST"]),
        ("/v1/tools", ok, ["POST"]),
        ("/mcp/", ok, ["POST"]),
        ("/oauth/token", ok, ["POST"]),
        ("/user-mcp/key/mcp", ok, ["POST"]),
        ("/static/app.js", ok, ["POST"]),
    ]
    app = Starlette()
    for path, endpoint, methods in routes:
        app.add_route(path, endpoint, methods=methods)
    return CSRFMiddleware(app, secret_key=SECRET)


@pytest.fixture()
def client():
    return TestClient(_build_app(), base_url="https://testserver")


def _post(client, path, **kwargs):
    return client.post(f"https://testserver{path}", **kwargs)


class TestSafeMethods:
    def test_get_passes_without_cookie(self, client):
        resp = _post_safe(client, "GET", "/form/submit")
        assert resp.status_code == 405  # GET not routed; reached router, not CSRF block

    def test_get_seeds_csrf_cookie(self, client):
        resp = client.get("https://testserver/form/submit")
        assert resp.status_code == 405
        assert "csrf_token" in resp.cookies

    def test_head_and_options_pass(self, client):
        assert client.options("https://testserver/form/submit").status_code != 403


def _post_safe(client, method, path):
    return client.request(method, f"https://testserver{path}")


class TestExemptPrefixes:
    @pytest.mark.parametrize(
        "path",
        [
            "/v1/tools",
            "/mcp/",
            "/oauth/token",
            "/user-mcp/key/mcp",
            "/static/app.js",
        ],
    )
    def test_exempt_paths_skip_csrf(self, client, path):
        resp = _post(client, path)
        assert resp.status_code != 403
        assert resp.text == "ok" if path != "/mcp/" else True


class TestFormPostValidation:
    def test_post_without_any_token_is_403(self, client):
        resp = _post(client, "/form/submit", data={"field": "x"})
        assert resp.status_code == 403
        assert resp.json() == {"error": "CSRF token validation failed"}

    def test_header_only_missing_cookie_is_403(self, client):
        resp = _post(
            client,
            "/form/submit",
            headers={"X-CSRF-Token": "some-token"},
        )
        assert resp.status_code == 403

    def test_mismatched_cookie_and_header_is_403(self, client):
        resp = _post(
            client,
            "/form/submit",
            cookies={"csrf_token": "cookie-value"},
            headers={"X-CSRF-Token": "different-value"},
        )
        assert resp.status_code == 403

    def test_matching_cookie_and_header_passes(self, client):
        resp = _post(
            client,
            "/form/submit",
            cookies={"csrf_token": "shared-token"},
            headers={"X-CSRF-Token": "shared-token"},
        )
        assert resp.status_code == 200

    def test_matching_cookie_and_form_field_passes(self, client):
        resp = _post(
            client,
            "/form/submit",
            cookies={"csrf_token": "shared-token"},
            data={"csrf_token": "shared-token", "field": "y"},
        )
        assert resp.status_code == 200
        assert resp.json()["posted"]["field"] == "y"

    def test_empty_strings_rejected(self, client):
        resp = _post(
            client,
            "/form/submit",
            cookies={"csrf_token": ""},
            headers={"X-CSRF-Token": ""},
        )
        assert resp.status_code == 403


class TestEndToEndWithSeededCookie:
    def test_flow_get_seed_then_post_with_header(self, client):
        # Step 1: any safe request seeds the double-submit cookie.
        seed = client.get("https://testserver/v1/tools")
        token = seed.cookies["csrf_token"]

        # Step 2: non-exempt form post must present the same token.
        resp = _post(
            client,
            "/form/submit",
            cookies={"csrf_token": token},
            headers={"X-CSRF-Token": token},
        )
        assert resp.status_code == 200

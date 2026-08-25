"""Tests for federated tool search across MCP backends and connectors."""

import asyncio
import json


def _state_with_sources():
    from gateway.server import AppState
    from auth.oauth import create_oauth_provider
    from auth.oauth_providers import create_oauth_provider as create_connector_oauth
    from backends.manager import BackendManager
    from connectors import ConnectorRegistry
    from config.settings import RelayConfig
    from security.middleware import (
        AuditLogger,
        InputValidator,
        IPRestrictions,
        RateLimiter,
        SecurityContext,
    )

    return AppState(
        config=RelayConfig(),
        oauth=create_oauth_provider("federated-search-secret"),
        connector_oauth=create_connector_oauth(RelayConfig()),
        security=SecurityContext(
            rate_limiter=RateLimiter(600, 10000),
            validator=InputValidator(),
            audit_logger=AuditLogger("/tmp/federated-search-audit.log", enabled=False),
            ip_restrictions=IPRestrictions(),
        ),
        backends=BackendManager(),
        connectors=ConnectorRegistry(),
    )


def test_gateway_search_tools_ranks_backend_and_connector_results(monkeypatch):
    from gateway.server import create_mcp_server

    app_state = _state_with_sources()

    class FakeFastMCP:
        registered = {}

        def __init__(self, *args, **kwargs):
            pass

        def tool(self):
            def decorator(function):
                self.registered[function.__name__] = function
                return function

            return decorator

    import mcp.server.fastmcp as fastmcp_module
    original_fastmcp = fastmcp_module.FastMCP
    fastmcp_module.FastMCP = FakeFastMCP
    try:
        create_mcp_server(app_state, init_state=False)
    finally:
        fastmcp_module.FastMCP = original_fastmcp

    monkeypatch.setattr(
        app_state.backends,
        "list_tools",
        lambda: [
            {
                "name": "repo_search",
                "backend_id": "github-mcp",
                "backend_name": "GitHub MCP",
            }
        ],
    )
    monkeypatch.setattr(
        app_state.connectors,
        "get_all_tools",
        lambda: [
            {
                "name": "search_repositories",
                "description": "Search GitHub repositories",
                "parameters": {"properties": {}},
                "connector": "github",
                "requires_auth": True,
            }
        ],
    )

    token = app_state.oauth.jwt.create_access_token(
        user_id="user-1", client_id="client-1", scope="mcp:tools"
    )
    raw = asyncio.run(FakeFastMCP.registered["gateway_search_tools"](
        query="search repo", authorization=f"Bearer {token}"
    ))
    response = json.loads(raw)

    assert response["total"] == 2
    assert {result["source"] for result in response["results"]} == {
        "gateway_call_tool",
        "connector:github",
    }
    assert all(result["score"] >= 1 for result in response["results"])

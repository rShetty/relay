"""
Integration tests for Patroclus client.

These tests verify the PatroclusClient HTTP client that Relay uses to
communicate with the Patroclus authorization server. They test both
the client logic and the end-to-end flow with a mock Patroclus server.
"""

import asyncio
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from patroclus import PatroclusClient


@pytest.fixture
def disabled_client():
    """A PatroclusClient that is disabled (passes through)."""
    return PatroclusClient(base_url="http://localhost:8484", enabled=False)


@pytest.fixture
def enabled_client():
    """A PatroclusClient that is enabled."""
    return PatroclusClient(base_url="http://localhost:8484", enabled=True, timeout_seconds=1.0)


class TestDisabledClient:
    """When Patroclus is disabled, all checks should pass through."""

    @pytest.mark.asyncio
    async def test_check_access_disabled_returns_allow(self, disabled_client):
        decision, reason = await disabled_client.check_access(
            agent_id="agent-1",
            action="call",
            resource="github/list_repos",
        )
        assert decision == "allow"
        assert "not enabled" in reason.lower()

    @pytest.mark.asyncio
    async def test_request_access_disabled_returns_allow(self, disabled_client):
        result = await disabled_client.request_access(
            agent_id="agent-1",
            action="call",
            resource="github/list_repos",
        )
        assert result["decision"] == "allow"
        assert result["token"] is None

    @pytest.mark.asyncio
    async def test_health_disabled_returns_false(self, disabled_client):
        assert await disabled_client.health() is False

    @pytest.mark.asyncio
    async def test_get_allowed_tools_returns_all_when_disabled(self, disabled_client):
        all_tools = ["tool1", "tool2", "tool3"]
        allowed = await disabled_client.get_allowed_tools("agent-1", "github", all_tools)
        assert allowed == all_tools


class TestEnabledClient:
    """When Patroclus is enabled, checks should call the server."""

    def _mock_client(self, enabled_client, response):
        """Set up a mock httpx client on the PatroclusClient."""
        mock_client = AsyncMock()
        mock_client.is_closed = False
        mock_client.post = AsyncMock(return_value=response)
        mock_client.get = AsyncMock(return_value=response)
        enabled_client._client = mock_client
        return mock_client

    @pytest.mark.asyncio
    async def test_check_access_allow(self, enabled_client):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "decision": "allow",
            "reason": "Permitted by policy",
            "allowed": True,
            "approved_scopes": ["github:list_repos"],
        }
        self._mock_client(enabled_client, mock_response)

        decision, reason = await enabled_client.check_access(
            agent_id="agent-1",
            action="call",
            resource="github/list_repos",
            requested_scopes=["github:list_repos"],
        )
        assert decision == "allow"
        assert "Permitted" in reason

    @pytest.mark.asyncio
    async def test_check_access_deny(self, enabled_client):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "decision": "deny",
            "reason": "No matching policy",
            "allowed": False,
            "approved_scopes": [],
        }
        self._mock_client(enabled_client, mock_response)

        decision, reason = await enabled_client.check_access(
            agent_id="agent-1",
            action="call",
            resource="github/delete_repo",
            requested_scopes=["github:delete_repo"],
        )
        assert decision == "deny"
        assert "No matching" in reason

    @pytest.mark.asyncio
    async def test_check_access_require_approval(self, enabled_client):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "decision": "require_approval",
            "reason": "Production write requires approval",
            "allowed": False,
            "approved_scopes": [],
        }
        self._mock_client(enabled_client, mock_response)

        decision, reason = await enabled_client.check_access(
            agent_id="agent-1",
            action="write",
            resource="prod-db/users",
            requested_scopes=["db:write"],
        )
        assert decision == "require_approval"
        assert "approval" in reason.lower()

    @pytest.mark.asyncio
    async def test_check_access_server_error_returns_deny(self, enabled_client):
        """If Patroclus returns an error, default to deny (fail closed)."""
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"
        self._mock_client(enabled_client, mock_response)

        decision, reason = await enabled_client.check_access(
            agent_id="agent-1",
            action="call",
            resource="github/list_repos",
        )
        assert decision == "deny"
        assert "500" in reason

    @pytest.mark.asyncio
    async def test_check_access_timeout_returns_deny(self, enabled_client):
        """If Patroclus times out, default to deny (fail closed)."""
        import httpx
        mock_client = AsyncMock()
        mock_client.is_closed = False
        mock_client.post = AsyncMock(side_effect=httpx.TimeoutException("timed out"))
        enabled_client._client = mock_client

        decision, reason = await enabled_client.check_access(
            agent_id="agent-1",
            action="call",
            resource="github/list_repos",
        )
        assert decision == "deny"
        assert "timed out" in reason.lower()

    @pytest.mark.asyncio
    async def test_request_access_returns_token_on_allow(self, enabled_client):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "decision": "allow",
            "reason": "Permitted",
            "token": {
                "jwt": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...",
                "jti": "01J5Q3Zabc",
                "scopes": ["github:list_repos"],
                "expires_at": "2026-08-14T12:00:00Z",
            },
            "approval": None,
            "approved_scopes": ["github:list_repos"],
        }
        self._mock_client(enabled_client, mock_response)

        result = await enabled_client.request_access(
            agent_id="agent-1",
            action="call",
            resource="github/list_repos",
            requested_scopes=["github:list_repos"],
        )
        assert result["decision"] == "allow"
        assert result["token"]["jwt"].startswith("eyJ")
        assert result["token"]["jti"] == "01J5Q3Zabc"

    @pytest.mark.asyncio
    async def test_request_access_returns_approval_on_require(self, enabled_client):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "decision": "require_approval",
            "reason": "Needs approval",
            "token": None,
            "approval": {
                "request_id": "01J5Q3Zdef",
                "status": "pending",
            },
            "approved_scopes": [],
        }
        self._mock_client(enabled_client, mock_response)

        result = await enabled_client.request_access(
            agent_id="agent-1",
            action="write",
            resource="prod-db/data",
        )
        assert result["decision"] == "require_approval"
        assert result["approval"]["request_id"] == "01J5Q3Zdef"
        assert result["approval"]["status"] == "pending"

    @pytest.mark.asyncio
    async def test_get_allowed_tools_filters(self, enabled_client):
        """get_allowed_tools should filter out denied tools."""
        responses = [
            MagicMock(
                status_code=200,
                json=MagicMock(return_value={
                    "decision": "allow", "reason": "ok", "allowed": True, "approved_scopes": []
                }),
            ),
            MagicMock(
                status_code=200,
                json=MagicMock(return_value={
                    "decision": "deny", "reason": "not allowed", "allowed": False, "approved_scopes": []
                }),
            ),
            MagicMock(
                status_code=200,
                json=MagicMock(return_value={
                    "decision": "allow", "reason": "ok", "allowed": True, "approved_scopes": []
                }),
            ),
        ]
        mock_client = AsyncMock()
        mock_client.is_closed = False
        mock_client.post = AsyncMock(side_effect=responses)
        enabled_client._client = mock_client

        all_tools = ["list_repos", "delete_repo", "create_issue"]
        allowed = await enabled_client.get_allowed_tools("agent-1", "github", all_tools)
        assert "list_repos" in allowed
        assert "delete_repo" not in allowed
        assert "create_issue" in allowed

    @pytest.mark.asyncio
    async def test_from_env_defaults(self):
        """PatroclusClient.from_env() should have sensible defaults."""
        import os
        old_url = os.environ.pop("PATROCLUS_URL", None)
        old_enabled = os.environ.pop("PATROCLUS_ENABLED", None)
        old_timeout = os.environ.pop("PATROCLUS_TIMEOUT", None)

        try:
            client = PatroclusClient.from_env()
            assert client.enabled is False
            assert client.base_url == "http://localhost:8484"
            assert client.timeout == 5.0
        finally:
            if old_url: os.environ["PATROCLUS_URL"] = old_url
            if old_enabled: os.environ["PATROCLUS_ENABLED"] = old_enabled
            if old_timeout: os.environ["PATROCLUS_TIMEOUT"] = old_timeout

    @pytest.mark.asyncio
    async def test_from_env_enabled(self):
        """PatroclusClient.from_env() should parse enabled=true."""
        import os
        os.environ["PATROCLUS_ENABLED"] = "true"
        os.environ["PATROCLUS_URL"] = "http://patroclus:8484"
        try:
            client = PatroclusClient.from_env()
            assert client.enabled is True
            assert client.base_url == "http://patroclus:8484"
        finally:
            os.environ.pop("PATROCLUS_ENABLED", None)
            os.environ.pop("PATROCLUS_URL", None)

"""
Patroclus Authorization Client

Integrates Relay's MCP gateway with Patroclus — the scoped, time-limited
authorization infrastructure for AI agents.

When an agent calls a tool through Relay, Relay asks Patroclus:
  "Is this agent allowed to perform this action on this resource?"

Patroclus evaluates policy and returns:
  - ALLOW: Relay proceeds with the tool call
  - DENY: Relay blocks the tool call
  - REQUIRE_APPROVAL: Relay pauses and creates an approval request

Flow:
  MCP Client → Relay (proxy) → Patroclus (policy check) → upstream MCP server
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, Optional, Tuple

import httpx

logger = logging.getLogger(__name__)


class PatroclusClient:
    """HTTP client for the Patroclus authorization API."""

    def __init__(
        self,
        base_url: str = "http://localhost:8484",
        timeout_seconds: float = 5.0,
        enabled: bool = True,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout_seconds
        self.enabled = enabled
        self._client: Optional[httpx.AsyncClient] = None

    @classmethod
    def from_env(cls) -> "PatroclusClient":
        """Create a PatroclusClient from environment variables."""
        base_url = os.getenv("PATROCLUS_URL", "http://localhost:8484")
        enabled = os.getenv("PATROCLUS_ENABLED", "false").lower() in ("true", "1", "yes")
        timeout = float(os.getenv("PATROCLUS_TIMEOUT", "5.0"))
        return cls(base_url=base_url, timeout_seconds=timeout, enabled=enabled)

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=self.timeout,
            )
        return self._client

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def health(self) -> bool:
        """Check if Patroclus is reachable."""
        if not self.enabled:
            return False
        try:
            client = await self._get_client()
            resp = await client.get("/health")
            return resp.status_code == 200
        except Exception:
            return False

    async def check_access(
        self,
        agent_id: str,
        action: str,
        resource: str,
        requested_scopes: Optional[list] = None,
        delegation_token: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[str, str]:
        """
        Dry-run policy check — does NOT issue a token.

        Returns (decision, reason) where decision is:
          "allow", "deny", or "require_approval"
        """
        if not self.enabled:
            return "allow", "Patroclus not enabled — defaulting to allow"

        payload: Dict[str, Any] = {
            "agent_id": agent_id,
            "action": action,
            "resource": resource,
            "requested_scopes": requested_scopes or [],
        }
        if delegation_token:
            payload["delegation_token"] = delegation_token
        if context:
            payload["context"] = context

        try:
            client = await self._get_client()
            resp = await client.post("/v1/agent/check", json=payload)
            if resp.status_code != 200:
                logger.warning(
                    "Patroclus check failed: %d %s",
                    resp.status_code,
                    resp.text,
                )
                return "deny", f"Patroclus check failed (HTTP {resp.status_code})"
            data = resp.json()
            decision = data.get("decision", "deny")
            reason = data.get("reason", "")
            return decision, reason
        except httpx.TimeoutException:
            logger.error("Patroclus check timed out for agent=%s action=%s", agent_id, action)
            return "deny", "Authorization check timed out"
        except Exception as e:
            logger.error("Patroclus check error: %s", e)
            return "deny", f"Authorization check error: {e}"

    async def request_access(
        self,
        agent_id: str,
        action: str,
        resource: str,
        requested_scopes: Optional[list] = None,
        delegation_token: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Full access request — issues a token on ALLOW, creates approval on
        REQUIRE_APPROVAL.

        Returns a dict with:
          - decision: "allow" | "deny" | "require_approval"
          - token: { jwt, jti, scopes, expires_at } or None
          - approval: { request_id, status } or None
          - reason: str
          - approved_scopes: list
        """
        if not self.enabled:
            return {
                "decision": "allow",
                "reason": "Patroclus not enabled",
                "token": None,
                "approval": None,
                "approved_scopes": [],
            }

        payload: Dict[str, Any] = {
            "agent_id": agent_id,
            "action": action,
            "resource": resource,
            "requested_scopes": requested_scopes or [],
        }
        if delegation_token:
            payload["delegation_token"] = delegation_token
        if context:
            payload["context"] = context

        try:
            client = await self._get_client()
            resp = await client.post("/v1/agent/request-access", json=payload)
            if resp.status_code != 200:
                logger.warning(
                    "Patroclus request-access failed: %d %s",
                    resp.status_code,
                    resp.text,
                )
                return {
                    "decision": "deny",
                    "reason": f"Patroclus returned HTTP {resp.status_code}",
                    "token": None,
                    "approval": None,
                    "approved_scopes": [],
                }
            return resp.json()
        except httpx.TimeoutException:
            logger.error("Patroclus request timed out for agent=%s", agent_id)
            return {
                "decision": "deny",
                "reason": "Authorization request timed out",
                "token": None,
                "approval": None,
                "approved_scopes": [],
            }
        except Exception as e:
            logger.error("Patroclus request error: %s", e)
            return {
                "decision": "deny",
                "reason": f"Authorization error: {e}",
                "token": None,
                "approval": None,
                "approved_scopes": [],
            }

    async def get_approval_status(self, request_id: str) -> Optional[Dict[str, Any]]:
        """Get the status of an approval request."""
        if not self.enabled:
            return None
        try:
            client = await self._get_client()
            resp = await client.get(f"/v1/agent/approval-status/{request_id}")
            if resp.status_code == 200:
                return resp.json()
            return None
        except Exception:
            return None

    async def approve_request(
        self,
        request_id: str,
        approver_id: str,
        reason: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Approve a pending approval request."""
        if not self.enabled:
            return None
        payload: Dict[str, Any] = {"approver_id": approver_id}
        if reason:
            payload["reason"] = reason
        try:
            client = await self._get_client()
            resp = await client.post(
                f"/v1/principal/approvals/{request_id}/approve",
                json=payload,
            )
            if resp.status_code == 200:
                return resp.json()
            return None
        except Exception:
            return None

    async def delegate_permissions(
        self,
        agent_id: str,
        scopes: list,
        expires_in_seconds: int = 900,
        constraints: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Delegate scoped permissions from a human principal to an agent.

        Returns the delegation response or None on failure.
        """
        if not self.enabled:
            return None
        payload: Dict[str, Any] = {
            "agent_id": agent_id,
            "scopes": scopes,
            "expires_in_seconds": expires_in_seconds,
        }
        if constraints:
            payload["constraints"] = constraints
        try:
            client = await self._get_client()
            resp = await client.post("/v1/principal/delegate", json=payload)
            if resp.status_code == 200:
                return resp.json()
            logger.warning("Patroclus delegation failed: %d", resp.status_code)
            return None
        except Exception as e:
            logger.error("Patroclus delegation error: %s", e)
            return None

    async def register_agent(
        self,
        name: str,
        principal_type: str = "delegated",
        owner_id: Optional[str] = None,
        public_key: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Register a new agent identity in Patroclus."""
        if not self.enabled:
            return None
        payload: Dict[str, Any] = {
            "name": name,
            "principal_type": principal_type,
        }
        if owner_id:
            payload["owner_id"] = owner_id
        if public_key:
            payload["public_key"] = public_key
        try:
            client = await self._get_client()
            resp = await client.post("/v1/admin/agents", json=payload)
            if resp.status_code == 200:
                return resp.json()
            return None
        except Exception as e:
            logger.error("Patroclus register agent error: %s", e)
            return None

    async def register_principal(
        self,
        external_id: str,
        email: str,
        display_name: str,
        idp_provider: str = "local",
    ) -> Optional[Dict[str, Any]]:
        """Register a new human principal in Patroclus."""
        if not self.enabled:
            return None
        payload = {
            "external_id": external_id,
            "idp_provider": idp_provider,
            "email": email,
            "display_name": display_name,
        }
        try:
            client = await self._get_client()
            resp = await client.post("/v1/admin/principals", json=payload)
            if resp.status_code == 200:
                return resp.json()
            return None
        except Exception as e:
            logger.error("Patroclus register principal error: %s", e)
            return None

    async def create_policy(
        self,
        name: str,
        definition: str,
        engine: str = "yaml",
    ) -> bool:
        """Create a new authorization policy in Patroclus."""
        if not self.enabled:
            return False
        payload = {"name": name, "engine": engine, "definition": definition}
        try:
            client = await self._get_client()
            resp = await client.post("/v1/admin/policies", json=payload)
            return resp.status_code == 200
        except Exception:
            return False

    async def get_allowed_tools(
        self,
        agent_id: str,
        connector_name: str,
        all_tools: list,
    ) -> list:
        """
        Filter a list of tool names based on what the agent is authorized to use.

        For each tool, checks if the agent is allowed to call it. Returns the
        filtered list.
        """
        if not self.enabled:
            return all_tools

        allowed = []
        for tool_name in all_tools:
            decision, _ = await self.check_access(
                agent_id=agent_id,
                action="call",
                resource=f"{connector_name}/{tool_name}",
                requested_scopes=[f"{connector_name}:{tool_name}"],
            )
            if decision == "allow":
                allowed.append(tool_name)
        return allowed

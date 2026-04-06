"""
Backend Manager for MCP Gateway

Manages connections to:
1. MCP servers (stdio and HTTP)
2. Direct API integrations

Provides a unified interface for routing tool calls to the appropriate backend.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Backend Types
# -----------------------------------------------------------------------------

class BackendType(Enum):
    """Type of backend integration."""
    MCP_STDIO = "mcp_stdio"
    MCP_HTTP = "mcp_http"
    API_REST = "api_rest"
    API_GRAPHQL = "api_graphql"


class BackendStatus(Enum):
    """Health status of a backend."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    DISCONNECTED = "disconnected"


class CircuitState(Enum):
    """Circuit breaker state for a backend."""
    CLOSED = "closed"        # Normal — requests pass through
    OPEN = "open"            # Failing — requests rejected immediately
    HALF_OPEN = "half_open"  # Recovery probe — one request allowed through


@dataclass
class BackendDefinition:
    """Configuration for a backend service."""
    id: str
    name: str
    description: str
    backend_type: BackendType
    enabled: bool = True
    requires_auth: bool = False
    env_key: Optional[str] = None
    connector: Optional[str] = None  # Maps to OAuth connector for per-user tokens
    tools: List[str] = field(default_factory=list)
    
    # MCP-specific
    command: Optional[str] = None
    args: List[str] = field(default_factory=list)
    env: Dict[str, str] = field(default_factory=dict)
    url: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    
    # API-specific
    base_url: Optional[str] = None
    auth_type: Optional[str] = None  # bearer, x-api-key, basic
    
    # Connection settings
    connect_timeout: int = 30
    tool_timeout: int = 120
    max_retries: int = 3

    # Circuit breaker
    circuit_breaker_threshold: int = 5   # consecutive failures before opening
    circuit_breaker_timeout: int = 60    # seconds before attempting half-open

    # Per-backend rate limiting (None = no cap beyond global limit)
    rate_limit_per_minute: Optional[int] = None


@dataclass
class BackendState:
    """Runtime state of a backend."""
    definition: BackendDefinition
    status: BackendStatus = BackendStatus.DISCONNECTED
    last_healthy: Optional[datetime] = None
    last_error: Optional[str] = None
    consecutive_failures: int = 0
    total_requests: int = 0
    total_errors: int = 0
    avg_latency_ms: float = 0.0
    
    # MCP session (for MCP backends)
    session: Optional[Any] = None

    # HTTP client (for API backends)
    http_client: Optional[Any] = None

    # Circuit breaker state
    circuit_state: CircuitState = CircuitState.CLOSED
    circuit_opened_at: Optional[datetime] = None


# -----------------------------------------------------------------------------
# MCP Backend Handler
# -----------------------------------------------------------------------------

class MCPBackendHandler:
    """
    Handles MCP server connections (stdio and HTTP).

    Each connection runs as a long-lived background asyncio Task so that the
    MCP SDK context managers (stdio_client / streamablehttp_client /
    ClientSession) remain open for the lifetime of the gateway process.
    A per-backend asyncio.Event signals readiness and a stop-Event triggers
    graceful shutdown.
    """

    def __init__(self):
        self._sessions: Dict[str, Any] = {}
        # background Task per backend_id
        self._tasks: Dict[str, asyncio.Task] = {}
        # set() to trigger disconnect
        self._stop_events: Dict[str, asyncio.Event] = {}

    async def connect_stdio(
        self,
        backend_id: str,
        command: str,
        args: List[str],
        env: Dict[str, str],
        timeout: int = 30,
    ) -> Tuple[bool, Optional[str]]:
        """
        Start and connect to an MCP server via stdio.

        Spawns a background Task that keeps the stdio_client context manager
        open until disconnect() is called.

        Returns:
            (success, error_message)
        """
        try:
            from mcp import ClientSession, StdioServerParameters
            from mcp.client.stdio import stdio_client
        except ImportError:
            return False, "MCP SDK not installed. Run: pip install mcp"

        # Build a safe, filtered environment for the subprocess
        process_env = os.environ.copy()
        process_env.update(env)
        safe_keys = {"PATH", "HOME", "USER", "LANG", "LC_ALL", "TERM", "SHELL", "TMPDIR"}
        filtered_env = {
            k: v for k, v in process_env.items()
            if k in safe_keys or k.startswith(("MCP_", "GITHUB_", "DATABASE_"))
        }
        filtered_env.update(env)

        server_params = StdioServerParameters(command=command, args=args, env=filtered_env)

        ready_event: asyncio.Event = asyncio.Event()
        stop_event: asyncio.Event = asyncio.Event()
        self._stop_events[backend_id] = stop_event
        error_box: List[str] = []

        async def _run() -> None:
            try:
                async with stdio_client(server_params) as (read, write):
                    async with ClientSession(read, write) as session:
                        await session.initialize()
                        self._sessions[backend_id] = session
                        logger.info(f"Connected to MCP backend: {backend_id}")
                        ready_event.set()
                        # Stay connected until disconnect() signals stop
                        await stop_event.wait()
            except Exception as exc:
                error_box.append(str(exc))
                ready_event.set()  # unblock the caller even on failure
            finally:
                self._sessions.pop(backend_id, None)
                logger.info(f"MCP stdio session ended: {backend_id}")

        task = asyncio.create_task(_run(), name=f"mcp-stdio-{backend_id}")
        self._tasks[backend_id] = task

        try:
            await asyncio.wait_for(ready_event.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            stop_event.set()
            task.cancel()
            return False, f"Connection timeout after {timeout}s"

        if error_box:
            return False, f"Connection failed: {error_box[0]}"

        return True, None

    async def connect_http(
        self,
        backend_id: str,
        url: str,
        headers: Dict[str, str],
        timeout: int = 30,
    ) -> Tuple[bool, Optional[str]]:
        """
        Connect to an MCP server via HTTP (streamable-HTTP transport).

        Runs as a background Task (same lifetime pattern as connect_stdio).

        Returns:
            (success, error_message)
        """
        try:
            from mcp import ClientSession
            from mcp.client.streamable_http import streamablehttp_client
            import httpx
        except ImportError:
            return False, "MCP SDK not installed. Run: pip install mcp"

        stop_event: asyncio.Event = asyncio.Event()
        self._stop_events[backend_id] = stop_event
        ready_event: asyncio.Event = asyncio.Event()
        error_box: List[str] = []

        async def _run() -> None:
            try:
                client_kwargs: Dict[str, Any] = {
                    "follow_redirects": True,
                    "timeout": httpx.Timeout(float(timeout), read=300.0),
                }
                if headers:
                    client_kwargs["headers"] = headers

                async with httpx.AsyncClient(**client_kwargs) as http_client:
                    async with streamablehttp_client(url, http_client=http_client) as (read, write, _):
                        async with ClientSession(read, write) as session:
                            await session.initialize()
                            self._sessions[backend_id] = session
                            logger.info(f"Connected to HTTP MCP backend: {backend_id}")
                            ready_event.set()
                            await stop_event.wait()
            except Exception as exc:
                error_box.append(str(exc))
                ready_event.set()
            finally:
                self._sessions.pop(backend_id, None)
                logger.info(f"MCP HTTP session ended: {backend_id}")

        task = asyncio.create_task(_run(), name=f"mcp-http-{backend_id}")
        self._tasks[backend_id] = task

        try:
            await asyncio.wait_for(ready_event.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            stop_event.set()
            task.cancel()
            return False, f"Connection timeout after {timeout}s"

        if error_box:
            return False, f"HTTP connection failed: {error_box[0]}"

        return True, None

    async def call_tool(
        self,
        backend_id: str,
        tool_name: str,
        arguments: Dict[str, Any],
        timeout: int = 120,
        user_token: Optional[str] = None,
    ) -> Tuple[bool, Any]:
        """
        Call a tool on an MCP backend.

        Args:
            backend_id: The backend ID
            tool_name: Name of the tool to call
            arguments: Tool arguments
            timeout: Timeout in seconds
            user_token: Optional per-user token (injected into env for subprocess)

        Returns:
            (success, result_or_error)
        """
        session = self._sessions.get(backend_id)
        if not session:
            return False, f"Backend {backend_id} not connected"

        # For MCP stdio, we need to pass the token via environment
        # Since we can't easily modify the running subprocess env,
        # we use a workaround: pass token via tool arguments if supported
        # Or restart the session with new token (heavier but works)
        if user_token:
            # Try to inject token - some MCP servers accept it via env
            # The MCP server process already has env set at startup
            # For per-user tokens, we'd need per-user sessions
            # For now, we'll pass it as part of the call
            arguments = {**arguments, "_user_token": user_token}

        try:
            async with asyncio.timeout(timeout):
                result = await session.call_tool(tool_name, arguments=arguments)

                if result.isError:
                    error_text = "".join(
                        block.text for block in (result.content or []) if hasattr(block, "text")
                    )
                    return False, error_text or "MCP tool error"

                parts = [
                    block.text for block in (result.content or []) if hasattr(block, "text")
                ]
                return True, "\n".join(parts) if parts else ""

        except asyncio.TimeoutError:
            return False, f"Tool call timeout after {timeout}s"
        except Exception as e:
            return False, f"Tool call failed: {e}"

    async def list_tools(self, backend_id: str) -> Tuple[bool, List[Dict[str, Any]]]:
        """List available tools from an MCP backend."""
        session = self._sessions.get(backend_id)
        if not session:
            return False, []

        try:
            result = await session.list_tools()
            tools = [
                {
                    "name": tool.name,
                    "description": getattr(tool, "description", ""),
                    "inputSchema": getattr(tool, "inputSchema", {}),
                }
                for tool in (result.tools if hasattr(result, "tools") else [])
            ]
            return True, tools
        except Exception as e:
            logger.error(f"Failed to list tools for {backend_id}: {e}")
            return False, []

    async def disconnect(self, backend_id: str) -> None:
        """Gracefully shut down the background session task for a backend."""
        stop_event = self._stop_events.pop(backend_id, None)
        if stop_event:
            stop_event.set()
        task = self._tasks.pop(backend_id, None)
        if task and not task.done():
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
        self._sessions.pop(backend_id, None)
        logger.info(f"Disconnected from MCP backend: {backend_id}")


# -----------------------------------------------------------------------------
# API Backend Handler
# -----------------------------------------------------------------------------

class APIBackendHandler:
    """
    Handles direct API integrations (REST and GraphQL).
    """

    def __init__(self):
        self._clients: Dict[str, Any] = {}

    async def get_client(self, backend_id: str, base_url: str, headers: Dict[str, str]):
        """Get or create an HTTP client for a backend."""
        if backend_id not in self._clients:
            import httpx
            self._clients[backend_id] = httpx.AsyncClient(
                base_url=base_url,
                headers=headers,
                timeout=httpx.Timeout(30.0, read=300.0),
                follow_redirects=True,
            )
        return self._clients[backend_id]

    async def call_rest(
        self,
        backend_id: str,
        base_url: str,
        headers: Dict[str, str],
        method: str,
        endpoint: str,
        json_data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        timeout: int = 120,
    ) -> Tuple[bool, Any]:
        """
        Make a REST API call.
        
        Returns:
            (success, result_or_error)
        """
        client = await self.get_client(backend_id, base_url, headers)
        
        try:
            async with asyncio.timeout(timeout):
                response = await client.request(
                    method=method,
                    url=endpoint,
                    json=json_data,
                    params=params,
                )
                
                if response.status_code >= 400:
                    return False, {
                        "error": f"API error {response.status_code}",
                        "body": response.text[:500],
                    }
                
                # Try JSON, fall back to text
                try:
                    return True, response.json()
                except Exception:
                    return True, {"text": response.text}
                    
        except asyncio.TimeoutError:
            return False, f"API call timeout after {timeout}s"
        except Exception as e:
            return False, f"API call failed: {e}"

    async def call_graphql(
        self,
        backend_id: str,
        base_url: str,
        headers: Dict[str, str],
        query: str,
        variables: Optional[Dict[str, Any]] = None,
        timeout: int = 120,
    ) -> Tuple[bool, Any]:
        """
        Make a GraphQL API call.
        
        Returns:
            (success, result_or_error)
        """
        json_data = {"query": query}
        if variables:
            json_data["variables"] = variables
        
        success, result = await self.call_rest(
            backend_id=backend_id,
            base_url=base_url,
            headers=headers,
            method="POST",
            endpoint="",  # Base URL is the GraphQL endpoint
            json_data=json_data,
            timeout=timeout,
        )
        
        if success and isinstance(result, dict):
            if "errors" in result:
                return False, {"errors": result["errors"]}
            return True, result.get("data", {})
        
        return success, result

    async def disconnect(self, backend_id: str) -> None:
        """Close HTTP client for a backend."""
        if backend_id in self._clients:
            await self._clients[backend_id].aclose()
            del self._clients[backend_id]


# -----------------------------------------------------------------------------
# Backend Manager
# -----------------------------------------------------------------------------

class BackendManager:
    """
    Central manager for all backend connections.
    
    Provides:
    - Backend registration and configuration
    - Connection management
    - Tool discovery and routing
    - Health monitoring
    """

    def __init__(
        self,
        health_check_interval: int = 30,
        unhealthy_threshold: int = 3,
    ):
        self._backends: Dict[str, BackendState] = {}
        self._mcp_handler = MCPBackendHandler()
        self._api_handler = APIBackendHandler()
        self._health_check_interval = health_check_interval
        self._unhealthy_threshold = unhealthy_threshold
        self._tool_index: Dict[str, str] = {}  # tool_name -> backend_id
        self._running = False
        # Per-backend rate limiters (only created when rate_limit_per_minute is set)
        self._per_backend_limiters: Dict[str, Any] = {}

    async def start(self) -> None:
        """Start the backend manager and health checks."""
        self._running = True
        asyncio.create_task(self._health_check_loop())
        logger.info("Backend manager started")

    async def stop(self) -> None:
        """Stop all backends and cleanup."""
        self._running = False
        for backend_id in list(self._backends.keys()):
            await self.disconnect_backend(backend_id)
        logger.info("Backend manager stopped")

    # -------------------------------------------------------------------------
    # Backend Registration
    # -------------------------------------------------------------------------

    def register_backend(self, definition: BackendDefinition) -> None:
        """Register a new backend."""
        if definition.id in self._backends:
            logger.warning(f"Backend {definition.id} already registered, replacing")

        state = BackendState(definition=definition)
        self._backends[definition.id] = state

        # Only index tools from static config if the list is non-empty.
        # MCP backends will populate tools dynamically after connection.
        # API backends inherit tool names from their connector mapping.
        for tool_name in definition.tools:
            self._tool_index[tool_name] = definition.id

        # Create per-backend rate limiter when a cap is configured
        if definition.rate_limit_per_minute is not None:
            from security.middleware import RateLimiter
            self._per_backend_limiters[definition.id] = RateLimiter(
                requests_per_minute=definition.rate_limit_per_minute,
                requests_per_hour=definition.rate_limit_per_minute * 60,
            )
            logger.info(
                f"Backend '{definition.id}': per-backend rate limit "
                f"{definition.rate_limit_per_minute} req/min"
            )

        logger.info(f"Registered backend: {definition.id} ({definition.backend_type.value})")

    async def _populate_mcp_tools(self, backend_id: str) -> None:
        """Discover tools from a live MCP session and update the index."""
        success, tools = await self._mcp_handler.list_tools(backend_id)
        if success:
            state = self._backends.get(backend_id)
            if state:
                old_tools = set(state.definition.tools)
                new_tools = [t["name"] for t in tools]
                state.definition.tools = new_tools
                
                for tool_name in old_tools:
                    if self._tool_index.get(tool_name) == backend_id:
                        del self._tool_index[tool_name]
                for tool_name in new_tools:
                    self._tool_index[tool_name] = backend_id
                
                logger.info(
                    f"Backend {backend_id}: discovered {len(new_tools)} tools "
                    f"from MCP server ({', '.join(new_tools[:5])}{'...' if len(new_tools) > 5 else ''})"
                )
        else:
            logger.warning(f"Failed to discover tools for MCP backend {backend_id}")

    def unregister_backend(self, backend_id: str) -> None:
        """Unregister a backend."""
        if backend_id in self._backends:
            state = self._backends[backend_id]
            # Remove tool index entries
            for tool_name in state.definition.tools:
                self._tool_index.pop(tool_name, None)
            del self._backends[backend_id]
            # Clean up per-backend rate limiter
            self._per_backend_limiters.pop(backend_id, None)
            logger.info(f"Unregistered backend: {backend_id}")

    def get_backend(self, backend_id: str) -> Optional[BackendState]:
        """Get backend state by ID."""
        return self._backends.get(backend_id)

    def list_backends(self) -> List[Dict[str, Any]]:
        """List all registered backends with their status."""
        result = []
        for backend_id, bstate in self._backends.items():
            circuit_info: Dict[str, Any] = {"state": bstate.circuit_state.value}
            if bstate.circuit_opened_at:
                elapsed = (datetime.now(timezone.utc) - bstate.circuit_opened_at).total_seconds()
                circuit_info["opened_ago_seconds"] = int(elapsed)
                circuit_info["retry_in_seconds"] = max(
                    0,
                    bstate.definition.circuit_breaker_timeout - int(elapsed),
                )
            result.append({
                "id": backend_id,
                "name": bstate.definition.name,
                "type": bstate.definition.backend_type.value,
                "status": bstate.status.value,
                "enabled": bstate.definition.enabled,
                "tools": bstate.definition.tools,
                "requires_auth": bstate.definition.requires_auth,
                "last_error": bstate.last_error,
                "circuit_breaker": circuit_info,
                "stats": {
                    "total_requests": bstate.total_requests,
                    "total_errors": bstate.total_errors,
                    "consecutive_failures": bstate.consecutive_failures,
                    "avg_latency_ms": round(bstate.avg_latency_ms, 1),
                },
            })
        return result

    # -------------------------------------------------------------------------
    # Connection Management
    # -------------------------------------------------------------------------

    async def connect_backend(self, backend_id: str) -> Tuple[bool, Optional[str]]:
        """
        Connect to a backend.
        
        Returns:
            (success, error_message)
        """
        state = self._backends.get(backend_id)
        if not state:
            return False, f"Backend {backend_id} not registered"
        
        definition = state.definition
        if not definition.enabled:
            return False, f"Backend {backend_id} is disabled"
        
        # Check if this is an admin-installed backend and load credentials
        installed_backend_creds = None
        try:
            from auth.database import get_installed_backend
            installed_backend = get_installed_backend(backend_id)
            if installed_backend:
                installed_backend_creds = installed_backend
                # Update definition with config from database
                config = installed_backend.get("config", {})
                if config.get("url"):
                    definition.url = config["url"]
                if config.get("base_url"):
                    definition.base_url = config["base_url"]
                if config.get("auth_type"):
                    definition.auth_type = config["auth_type"]
                logger.info(f"Loaded configuration for installed backend: {backend_id}")
        except Exception as e:
            logger.warning(f"Could not load installed backend config for {backend_id}: {e}")
        
        # Check for required credentials
        if definition.env_key and not os.getenv(definition.env_key):
            # If this is an installed backend, use the stored client_secret
            if installed_backend_creds and installed_backend_creds.get("client_secret"):
                # Use stored credentials for installed backends
                pass
            else:
                return False, f"Missing required credential: {definition.env_key}"
        
        start_time = time.time()
        
        if definition.backend_type == BackendType.MCP_STDIO:
            success, error = await self._mcp_handler.connect_stdio(
                backend_id=backend_id,
                command=definition.command,
                args=definition.args,
                env=definition.env,
                timeout=definition.connect_timeout,
            )
        elif definition.backend_type == BackendType.MCP_HTTP:
            # Prepare headers with installed backend credentials if available
            headers = definition.headers.copy()
            if installed_backend_creds:
                client_id = installed_backend_creds.get("client_id")
                client_secret = installed_backend_creds.get("client_secret")
                if client_id and client_secret:
                    # Add basic auth header
                    import base64
                    auth_str = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
                    headers["Authorization"] = f"Basic {auth_str}"
            
            success, error = await self._mcp_handler.connect_http(
                backend_id=backend_id,
                url=definition.url,
                headers=headers,
                timeout=definition.connect_timeout,
            )
        else:
            # API backends don\'t need explicit connection
            success, error = True, None
        
        latency_ms = (time.time() - start_time) * 1000
        state.avg_latency_ms = latency_ms
        
        if success:
            state.status = BackendStatus.HEALTHY
            state.last_healthy = datetime.now(timezone.utc)
            state.consecutive_failures = 0
            logger.info(f"Connected to backend: {backend_id} ({latency_ms:.0f}ms)")
            
            if definition.backend_type in (BackendType.MCP_STDIO, BackendType.MCP_HTTP):
                await self._populate_mcp_tools(backend_id)
        else:
            state.status = BackendStatus.UNHEALTHY
            state.last_error = error
            state.consecutive_failures += 1
            logger.error(f"Failed to connect to {backend_id}: {error}")
        
        return success, error

    async def disconnect_backend(self, backend_id: str) -> None:
        """Disconnect from a backend."""
        state = self._backends.get(backend_id)
        if not state:
            return
        
        definition = state.definition
        
        if definition.backend_type in (BackendType.MCP_STDIO, BackendType.MCP_HTTP):
            await self._mcp_handler.disconnect(backend_id)
        else:
            await self._api_handler.disconnect(backend_id)
        
        state.status = BackendStatus.DISCONNECTED
        state.session = None
        state.http_client = None

    async def connect_all(self) -> Dict[str, Tuple[bool, Optional[str]]]:
        """Connect to all registered backends."""
        results = {}
        for backend_id, state in self._backends.items():
            if state.definition.enabled:
                results[backend_id] = await self.connect_backend(backend_id)
        return results

    # -------------------------------------------------------------------------
    # Tool Routing
    # -------------------------------------------------------------------------

    def get_backend_for_tool(self, tool_name: str) -> Optional[str]:
        """Find which backend provides a tool."""
        return self._tool_index.get(tool_name)

    def list_tools(self) -> List[Dict[str, Any]]:
        """List all available tools across backends."""
        tools = []
        for tool_name, backend_id in self._tool_index.items():
            state = self._backends.get(backend_id)
            if state and state.status == BackendStatus.HEALTHY:
                tools.append({
                    "name": tool_name,
                    "backend_id": backend_id,
                    "backend_name": state.definition.name,
                })
        return tools

    async def call_tool(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        backend_id: Optional[str] = None,
        timeout: int = 120,
        user_token: Optional[str] = None,
    ) -> Tuple[bool, Any]:
        """
        Call a tool, routing to the appropriate backend.
        
        Args:
            tool_name: Name of the tool to call
            arguments: Tool arguments
            backend_id: Optional backend ID (auto-resolved if not provided)
            timeout: Timeout in seconds
            user_token: Optional per-user token for OAuth-authenticated backends
            
        Returns:
            (success, result_or_error)
        """
        if backend_id is None:
            backend_id = self._tool_index.get(tool_name)
        
        if not backend_id:
            return False, f"Tool {tool_name} not found"

        bstate = self._backends.get(backend_id)
        if not bstate:
            return False, f"Backend {backend_id} not found"

        # ---- Circuit breaker check ----------------------------------------
        if bstate.circuit_state == CircuitState.OPEN:
            now = datetime.now(timezone.utc)
            if bstate.circuit_opened_at:
                elapsed = (now - bstate.circuit_opened_at).total_seconds()
                if elapsed >= bstate.definition.circuit_breaker_timeout:
                    bstate.circuit_state = CircuitState.HALF_OPEN
                    logger.info(
                        f"Circuit half-open for '{backend_id}' after {int(elapsed)}s — probing recovery"
                    )
                else:
                    remaining = int(bstate.definition.circuit_breaker_timeout - elapsed)
                    return False, (
                        f"Circuit breaker open for backend '{backend_id}'. "
                        f"Retry in {remaining}s."
                    )
            else:
                return False, f"Circuit breaker open for backend '{backend_id}'"

        if bstate.status != BackendStatus.HEALTHY and bstate.circuit_state == CircuitState.CLOSED:
            return False, f"Backend {backend_id} is not healthy ({bstate.status.value})"

        # ---- Per-backend rate limit check ------------------------------------
        if backend_id in self._per_backend_limiters:
            allowed, rl_info = self._per_backend_limiters[backend_id].is_allowed(backend_id)
            if not allowed:
                reason = rl_info.get("reason", "limit reached")
                retry_after = rl_info.get("retry_after", 60)
                return False, (
                    f"Backend '{backend_id}' rate limit exceeded ({reason}). "
                    f"Retry after {retry_after}s."
                )

        # Use a local alias so the name doesn't shadow anything below
        state = bstate
        definition = state.definition
        start_time = time.time()
        
        try:
            if definition.backend_type == BackendType.MCP_STDIO:
                success, result = await self._mcp_handler.call_tool(
                    backend_id=backend_id,
                    tool_name=tool_name,
                    arguments=arguments,
                    timeout=timeout,
                    user_token=user_token,
                )
            elif definition.backend_type == BackendType.MCP_HTTP:
                success, result = await self._mcp_handler.call_tool(
                    backend_id=backend_id,
                    tool_name=tool_name,
                    arguments=arguments,
                    timeout=timeout,
                    user_token=user_token,
                )
            elif definition.backend_type == BackendType.API_REST:
                success, result = await self._call_api_tool(
                    definition, tool_name, arguments, timeout, user_token
                )
            elif definition.backend_type == BackendType.API_GRAPHQL:
                success, result = await self._call_graphql_tool(
                    definition, tool_name, arguments, timeout, user_token
                )
            else:
                return False, f"Unsupported backend type: {definition.backend_type}"
            
            latency_ms = (time.time() - start_time) * 1000
            state.total_requests += 1
            state.avg_latency_ms = (state.avg_latency_ms + latency_ms) / 2

            if not success:
                state.total_errors += 1
                state.consecutive_failures += 1
                # Circuit breaker: failure during half-open probe → reopen
                if state.circuit_state == CircuitState.HALF_OPEN:
                    state.circuit_state = CircuitState.OPEN
                    state.circuit_opened_at = datetime.now(timezone.utc)
                    logger.warning(
                        f"Circuit reopened for '{backend_id}': probe call still failing"
                    )
                elif state.consecutive_failures >= definition.circuit_breaker_threshold:
                    state.circuit_state = CircuitState.OPEN
                    state.circuit_opened_at = datetime.now(timezone.utc)
                    state.status = BackendStatus.UNHEALTHY
                    logger.warning(
                        f"Circuit opened for '{backend_id}' after "
                        f"{state.consecutive_failures} consecutive failures"
                    )
                elif state.consecutive_failures >= self._unhealthy_threshold:
                    state.status = BackendStatus.UNHEALTHY
            else:
                if state.circuit_state == CircuitState.HALF_OPEN:
                    state.circuit_state = CircuitState.CLOSED
                    state.circuit_opened_at = None
                    state.status = BackendStatus.HEALTHY
                    logger.info(f"Circuit closed for '{backend_id}': backend has recovered")
                state.consecutive_failures = 0
                state.last_healthy = datetime.now(timezone.utc)

            return success, result

        except Exception as e:
            state.total_errors += 1
            state.consecutive_failures += 1
            state.last_error = str(e)
            # Update circuit state for unexpected exceptions (same logic as failure path)
            if state.circuit_state == CircuitState.HALF_OPEN:
                state.circuit_state = CircuitState.OPEN
                state.circuit_opened_at = datetime.now(timezone.utc)
                logger.warning(f"Circuit reopened for '{backend_id}': exception during probe")
            elif state.consecutive_failures >= definition.circuit_breaker_threshold:
                state.circuit_state = CircuitState.OPEN
                state.circuit_opened_at = datetime.now(timezone.utc)
                state.status = BackendStatus.UNHEALTHY
                logger.warning(f"Circuit opened for '{backend_id}' after exception")
            return False, f"Tool call failed: {e}"

    async def _call_api_tool(
        self,
        definition: BackendDefinition,
        tool_name: str,
        arguments: Dict[str, Any],
        timeout: int,
        user_token: Optional[str] = None,
    ) -> Tuple[bool, Any]:
        """
        Call a tool on an API backend by delegating to the connector\'s
        tool-specific handler.  This avoids the old stub that blindly
        POSTed to /{tool_name}.
        """
        from connectors import get_registry, ConnectorConfig

        # Try to get credentials in this order: user_token, installed backend, env var
        cred = user_token if user_token else None
        
        # Check if this is an admin-installed backend and use stored credentials
        if not cred:
            try:
                from auth.database import get_installed_backend
                installed_backend = get_installed_backend(definition.id)
                if installed_backend:
                    # For installed backends, use client_secret as the API key/token
                    cred = installed_backend.get("client_secret")
                    logger.debug(f"Using installed backend credentials for {definition.id}")
            except Exception as e:
                logger.warning(f"Could not load installed backend credentials for {definition.id}: {e}")
        
        # Fall back to environment variable
        if not cred:
            cred = os.getenv(definition.env_key, "")
        
        if not cred:
            return False, (
                f"No credentials for \'{definition.id}\'. "
                f"Set {definition.env_key} or store a token via POST /v1/tokens."
            )

        connector_name = definition.connector or definition.id
        registry = get_registry()
        conn_class = registry.CONNECTOR_TYPES.get(connector_name)
        if conn_class is None:
            return False, f"No connector class for \'{connector_name}\'"

        config = ConnectorConfig(api_key=cred, base_url=definition.base_url)
        connector = conn_class(config)
        try:
            success, result = await connector.call_tool(tool_name, arguments)
            return success, result
        finally:
            await connector.close()

    async def _call_graphql_tool(
        self,
        definition: BackendDefinition,
        tool_name: str,
        arguments: Dict[str, Any],
        timeout: int,
        user_token: Optional[str] = None,
    ) -> Tuple[bool, Any]:
        """
        Call a tool on a GraphQL API backend by delegating to the connector\'s
        tool-specific handler (which already knows how to build GraphQL queries).
        """
        from connectors import get_registry, ConnectorConfig

        # Try to get credentials in this order: user_token, installed backend, env var
        cred = user_token if user_token else None
        
        # Check if this is an admin-installed backend and use stored credentials
        if not cred:
            try:
                from auth.database import get_installed_backend
                installed_backend = get_installed_backend(definition.id)
                if installed_backend:
                    # For installed backends, use client_secret as the API key/token
                    cred = installed_backend.get("client_secret")
                    logger.debug(f"Using installed backend credentials for {definition.id}")
            except Exception as e:
                logger.warning(f"Could not load installed backend credentials for {definition.id}: {e}")
        
        # Fall back to environment variable
        if not cred:
            cred = os.getenv(definition.env_key, "")
        
        if not cred:
            return False, (
                f"No credentials for \'{definition.id}\'. "
                f"Set {definition.env_key} or store a token via POST /v1/tokens."
            )

        connector_name = definition.connector or definition.id
        registry = get_registry()
        conn_class = registry.CONNECTOR_TYPES.get(connector_name)
        if conn_class is None:
            return False, f"No connector class for \'{connector_name}\'"

        config = ConnectorConfig(api_key=cred, base_url=definition.base_url)
        connector = conn_class(config)
        try:
            success, result = await connector.call_tool(tool_name, arguments)
            return success, result
        finally:
            await connector.close()
        """
        Call a tool on an API backend by delegating to the connector's
        tool-specific handler.  This avoids the old stub that blindly
        POSTed to /{tool_name}.
        """
        from connectors import get_registry, ConnectorConfig

        cred = user_token if user_token else os.getenv(definition.env_key, "")
        if not cred:
            return False, (
                f"No credentials for '{definition.id}'. "
                f"Set {definition.env_key} or store a token via POST /v1/tokens."
            )

        connector_name = definition.connector or definition.id
        registry = get_registry()
        conn_class = registry.CONNECTOR_TYPES.get(connector_name)
        if conn_class is None:
            return False, f"No connector class for '{connector_name}'"

        config = ConnectorConfig(api_key=cred, base_url=definition.base_url)
        connector = conn_class(config)
        try:
            success, result = await connector.call_tool(tool_name, arguments)
            return success, result
        finally:
            await connector.close()

    async def _call_graphql_tool(
        self,
        definition: BackendDefinition,
        tool_name: str,
        arguments: Dict[str, Any],
        timeout: int,
        user_token: Optional[str] = None,
    ) -> Tuple[bool, Any]:
        """
        Call a tool on a GraphQL API backend by delegating to the connector's
        tool-specific handler (which already knows how to build GraphQL queries).
        """
        from connectors import get_registry, ConnectorConfig

        cred = user_token if user_token else os.getenv(definition.env_key, "")
        if not cred:
            return False, (
                f"No credentials for '{definition.id}'. "
                f"Set {definition.env_key} or store a token via POST /v1/tokens."
            )

        connector_name = definition.connector or definition.id
        registry = get_registry()
        conn_class = registry.CONNECTOR_TYPES.get(connector_name)
        if conn_class is None:
            return False, f"No connector class for '{connector_name}'"

        config = ConnectorConfig(api_key=cred, base_url=definition.base_url)
        connector = conn_class(config)
        try:
            success, result = await connector.call_tool(tool_name, arguments)
            return success, result
        finally:
            await connector.close()

    # -------------------------------------------------------------------------
    # Health Monitoring
    # -------------------------------------------------------------------------

    async def _health_check_loop(self) -> None:
        """Periodically check backend health."""
        while self._running:
            await asyncio.sleep(self._health_check_interval)
            await self._check_all_health()

    async def _check_all_health(self) -> None:
        """Check health of all backends."""
        for backend_id, bstate in self._backends.items():
            if not bstate.definition.enabled:
                continue

            # MCP backends: try to list tools
            if bstate.definition.backend_type in (BackendType.MCP_STDIO, BackendType.MCP_HTTP):
                success, tools = await self._mcp_handler.list_tools(backend_id)
                if success:
                    bstate.status = BackendStatus.HEALTHY
                    bstate.last_healthy = datetime.now(timezone.utc)
                    bstate.consecutive_failures = 0
                    # Reset circuit breaker if it was open
                    if bstate.circuit_state != CircuitState.CLOSED:
                        bstate.circuit_state = CircuitState.CLOSED
                        bstate.circuit_opened_at = None
                        logger.info(f"Circuit reset for '{backend_id}' after health-check recovery")
                else:
                    bstate.consecutive_failures += 1
                    if bstate.consecutive_failures >= bstate.definition.circuit_breaker_threshold:
                        if bstate.circuit_state == CircuitState.CLOSED:
                            bstate.circuit_state = CircuitState.OPEN
                            bstate.circuit_opened_at = datetime.now(timezone.utc)
                            logger.warning(f"Circuit opened for '{backend_id}' via health-check failures")
                    if bstate.consecutive_failures >= self._unhealthy_threshold:
                        bstate.status = BackendStatus.UNHEALTHY

            # API backends: simple ping
            else:
                try:
                    success, _ = await self._api_handler.call_rest(
                        backend_id=backend_id,
                        base_url=bstate.definition.base_url,
                        headers=bstate.definition.headers,
                        method="GET",
                        endpoint="",
                        timeout=10,
                    )
                    if success:
                        bstate.status = BackendStatus.HEALTHY
                        bstate.consecutive_failures = 0
                        if bstate.circuit_state != CircuitState.CLOSED:
                            bstate.circuit_state = CircuitState.CLOSED
                            bstate.circuit_opened_at = None
                            logger.info(f"Circuit reset for '{backend_id}' after health-check recovery")
                except Exception:
                    bstate.consecutive_failures += 1
                    if bstate.consecutive_failures >= bstate.definition.circuit_breaker_threshold:
                        if bstate.circuit_state == CircuitState.CLOSED:
                            bstate.circuit_state = CircuitState.OPEN
                            bstate.circuit_opened_at = datetime.now(timezone.utc)

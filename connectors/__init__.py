"""
Connector Registry for Relay

Manages all third-party connectors and provides:
- Connector registration and discovery
- Tool routing to appropriate connector
- Health monitoring
- Credential management
"""

from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Type

from .github import BaseConnector, ConnectorConfig, ToolDefinition
from .github import ResourceDefinition, PromptDefinition
from .github import GitHubConnector
from .slack import SlackConnector
from .linear import LinearConnector
from .ai_providers import OpenAIConnector, AnthropicConnector

logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Connector Registry
# -----------------------------------------------------------------------------

@dataclass
class ConnectorState:
    """Runtime state of a connector."""
    connector: BaseConnector
    enabled: bool = True
    healthy: bool = False
    last_health_check: Optional[datetime] = None
    total_calls: int = 0
    total_errors: int = 0


class ConnectorRegistry:
    """
    Central registry for all third-party connectors.
    
    Features:
    - Auto-discovers tools from all registered connectors
    - Routes tool calls to the appropriate connector
    - Manages health checks
    - Handles credential resolution from environment
    """
    
    # Built-in connector types
    CONNECTOR_TYPES: Dict[str, Type[BaseConnector]] = {
        "github": GitHubConnector,
        "slack": SlackConnector,
        "linear": LinearConnector,
        "openai": OpenAIConnector,
        "anthropic": AnthropicConnector,
    }
    
    # Environment variable mappings for credentials
    CREDENTIAL_ENV_KEYS: Dict[str, str] = {
        "github": "GITHUB_PERSONAL_ACCESS_TOKEN",
        "slack": "SLACK_BOT_TOKEN",
        "linear": "LINEAR_API_KEY",
        "openai": "OPENAI_API_KEY",
        "anthropic": "ANTHROPIC_API_KEY",
    }
    
    def __init__(self, health_check_interval: int = 300):
        """
        Initialize the connector registry.
        
        Args:
            health_check_interval: Seconds between health checks (default 5 min)
        """
        self._connectors: Dict[str, ConnectorState] = {}
        self._tool_index: Dict[str, str] = {}  # tool_name -> connector_name
        self._health_check_interval = health_check_interval
        self._running = False
    
    # -------------------------------------------------------------------------
    # Connector Registration
    # -------------------------------------------------------------------------
    
    async def register_connector_async(
        self,
        name: str,
        connector: BaseConnector,
        enabled: bool = True,
    ) -> None:
        """
        Register a connector instance with async tool discovery.
        
        Args:
            name: Unique name for this connector
            connector: Connector instance
            enabled: Whether the connector is active
        """
        if name in self._connectors:
            logger.warning(f"Connector '{name}' already registered, replacing")
        
        self._connectors[name] = ConnectorState(
            connector=connector,
            enabled=enabled,
        )
        
        # Index tools - try async first, fallback to sync
        tools = []
        has_async = hasattr(connector, "get_tools_async")
        logger.info(f"  Connector '{name}': has get_tools_async={has_async}")
        if has_async:
            try:
                tools = await connector.get_tools_async()
                logger.info(f"  Connector '{name}': discovered {len(tools)} tools via async")
            except Exception as e:
                logger.warning(f"  Connector '{name}': async tool discovery failed: {e}, using sync")
                tools = connector.get_tools()
        else:
            tools = connector.get_tools()
        
        for tool in tools:
            if tool.name in self._tool_index:
                logger.warning(
                    f"Tool '{tool.name}' already registered by '{self._tool_index[tool.name]}', "
                    f"now also available from '{name}'"
                )
            self._tool_index[tool.name] = name
        
        logger.info(f"Registered connector '{name}' with {len(tools)} tools")
    
    def register_connector(
        self,
        name: str,
        connector: BaseConnector,
        enabled: bool = True,
    ) -> None:
        """
        Register a connector instance.
        
        Args:
            name: Unique name for this connector
            connector: Connector instance
            enabled: Whether the connector is active
        """
        if name in self._connectors:
            logger.warning(f"Connector '{name}' already registered, replacing")
        
        self._connectors[name] = ConnectorState(
            connector=connector,
            enabled=enabled,
        )
        
        # Index all tools from this connector
        for tool in connector.get_tools():
            if tool.name in self._tool_index:
                logger.warning(
                    f"Tool '{tool.name}' already registered by '{self._tool_index[tool.name]}', "
                    f"now also available from '{name}'"
                )
            self._tool_index[tool.name] = name
        
        logger.info(f"Registered connector '{name}' with {len(connector.get_tools())} tools")
    
    def register_from_env(self, name: Optional[str] = None) -> List[str]:
        """
        Register connectors from environment variables.
        
        Scans for credentials and auto-registers connectors that have them.
        
        Args:
            name: Optional specific connector to register (registers all if None)
        
        Returns:
            List of registered connector names
        """
        registered = []
        
        for conn_name, conn_class in self.CONNECTOR_TYPES.items():
            if name and conn_name != name:
                continue
            
            env_key = self.CREDENTIAL_ENV_KEYS.get(conn_name)
            if not env_key:
                continue
            
            api_key = os.getenv(env_key)
            if not api_key:
                logger.debug(f"No credential found for {conn_name} ({env_key})")
                continue
            
            config = ConnectorConfig(api_key=api_key)
            connector = conn_class(config)
            self.register_connector(conn_name, connector)
            registered.append(conn_name)
        
        return registered
    
    def unregister_connector(self, name: str) -> bool:
        """
        Unregister a connector.
        
        Args:
            name: Connector name
        
        Returns:
            True if connector was removed
        """
        if name not in self._connectors:
            return False
        
        state = self._connectors[name]
        
        # Remove tools from index
        for tool in state.connector.get_tools():
            if self._tool_index.get(tool.name) == name:
                del self._tool_index[tool.name]
        
        del self._connectors[name]
        logger.info(f"Unregistered connector '{name}'")
        return True
    
    def get_connector(self, name: str) -> Optional[BaseConnector]:
        """Get a connector by name."""
        state = self._connectors.get(name)
        return state.connector if state else None
    
    def list_connectors(self) -> List[Dict[str, Any]]:
        """List all registered connectors with their status."""
        result = []
        for name, state in self._connectors.items():
            result.append({
                "name": name,
                "display_name": state.connector.display_name,
                "description": state.connector.description,
                "enabled": state.enabled,
                "healthy": state.healthy,
                "tools": [t.name for t in state.connector.get_tools()],
                "total_calls": state.total_calls,
                "total_errors": state.total_errors,
                "last_health_check": state.last_health_check.isoformat() if state.last_health_check else None,
            })
        return result
    
    async def list_connectors_async(self) -> List[Dict[str, Any]]:
        """List all registered connectors with their status (async tool discovery)."""
        result = []
        for name, state in self._connectors.items():
            # Try async tool discovery first, fall back to sync
            try:
                if hasattr(state.connector, "get_tools_async"):
                    tools = await state.connector.get_tools_async()
                else:
                    tools = state.connector.get_tools()
            except Exception:
                tools = state.connector.get_tools()
            
            result.append({
                "name": name,
                "display_name": state.connector.display_name,
                "description": state.connector.description,
                "enabled": state.enabled,
                "healthy": state.healthy,
                "tools": [t.name for t in tools],
                "total_calls": state.total_calls,
                "total_errors": state.total_errors,
                "last_health_check": state.last_health_check.isoformat() if state.last_health_check else None,
            })
        return result
    
    # -------------------------------------------------------------------------
    # Tool Discovery
    # -------------------------------------------------------------------------
    
    def get_all_tools(self) -> List[Dict[str, Any]]:
        """Get all tools from all registered connectors."""
        tools = []
        seen_names = set()
        
        for name, state in self._connectors.items():
            if not state.enabled:
                continue
            
            for tool in state.connector.get_tools():
                if tool.name in seen_names:
                    continue
                seen_names.add(tool.name)
                
                tools.append({
                    "name": tool.name,
                    "description": tool.description,
                    "parameters": tool.parameters,
                    "connector": name,
                    "requires_auth": tool.requires_auth,
                })
        
        return tools
    
    def get_all_resources(self) -> List[Dict[str, Any]]:
        """Get all resources from all registered connectors."""
        resources = []
        
        for name, state in self._connectors.items():
            if not state.enabled:
                continue
            
            for resource in state.connector.get_resources():
                resources.append({
                    "uri": resource.uri,
                    "name": resource.name,
                    "description": resource.description,
                    "mime_type": resource.mime_type,
                    "connector": name,
                    "requires_auth": resource.requires_auth,
                })
        
        return resources
    
    def get_all_prompts(self) -> List[Dict[str, Any]]:
        """Get all prompts from all registered connectors."""
        prompts = []
        
        for name, state in self._connectors.items():
            if not state.enabled:
                continue
            
            for prompt in state.connector.get_prompts():
                prompts.append({
                    "name": prompt.name,
                    "description": prompt.description,
                    "arguments": prompt.arguments,
                    "template": prompt.template,
                    "connector": name,
                    "requires_auth": prompt.requires_auth,
                })
        
        return prompts
    
    async def read_resource(self, uri: str, user_token: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Read a resource by URI."""
        # Find connector that owns this URI
        for name, state in self._connectors.items():
            if not state.enabled:
                continue
            
            # Set token if provided
            if user_token and hasattr(state.connector, "set_token"):
                state.connector.set_token(user_token)
            
            result = await state.connector.read_resource(uri)
            if result and "error" not in result:
                return result
        
        return None
    
    def get_tool_schema(self, tool_name: str) -> Optional[Dict[str, Any]]:
        """Get JSON Schema for a specific tool."""
        connector_name = self._tool_index.get(tool_name)
        if not connector_name:
            return None
        
        state = self._connectors.get(connector_name)
        if not state:
            return None
        
        for tool in state.connector.get_tools():
            if tool.name == tool_name:
                return {
                    "name": tool.name,
                    "description": tool.description,
                    "inputSchema": {
                        "type": "object",
                        **tool.parameters,
                    },
                }
        
        return None
    
    # -------------------------------------------------------------------------
    # Tool Execution
    # -------------------------------------------------------------------------
    
    async def call_tool(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        user_token: Optional[str] = None,
    ) -> Tuple[bool, Any]:
        """
        Call a tool by name.

        Credential resolution order:
        1. ``user_token`` — caller-supplied per-user credential (from TokenStore)
        2. Shared credential configured on the registered connector (env var at startup)
        3. Error: credentials required

        Args:
            tool_name: Name of the tool to call
            arguments: Tool arguments
            user_token: Optional per-user API token that overrides the shared credential

        Returns:
            Tuple of (success, result_or_error)
        """
        connector_name = self._tool_index.get(tool_name)
        if not connector_name:
            return False, {"error": f"Unknown tool: {tool_name}"}

        conn_state = self._connectors.get(connector_name)
        if not conn_state:
            return False, {"error": f"Connector not found: {connector_name}"}

        if not conn_state.enabled:
            return False, {"error": f"Connector '{connector_name}' is disabled"}

        # Resolve which connector instance to use
        if user_token:
            # Build a fresh per-request connector with the user's own credential
            conn_class = self.CONNECTOR_TYPES.get(connector_name)
            if conn_class is None:
                return False, {"error": f"No class registered for connector '{connector_name}'"}
            from connectors.github import ConnectorConfig
            connector = conn_class(ConnectorConfig(api_key=user_token))
            owns_connector = True
        elif conn_state.connector.config.api_key:
            # Use the shared connector registered at startup
            connector = conn_state.connector
            owns_connector = False
        else:
            env_key = self.CREDENTIAL_ENV_KEYS.get(connector_name, connector_name.upper() + "_API_KEY")
            return False, {
                "error": (
                    f"No credentials configured for '{connector_name}'. "
                    f"Set {env_key} as an environment variable (shared), "
                    f"or store your personal token via POST /v1/tokens."
                )
            }

        try:
            success, result = await connector.call_tool(tool_name, arguments)
            conn_state.total_calls += 1
            if not success:
                conn_state.total_errors += 1
            return success, result
        except Exception as e:
            conn_state.total_errors += 1
            logger.error(f"Tool call failed: {tool_name}: {e}")
            return False, {"error": str(e)}
        finally:
            if owns_connector:
                await connector.close()
    
    # -------------------------------------------------------------------------
    # Health Monitoring
    # -------------------------------------------------------------------------
    
    async def start_health_checks(self) -> None:
        """Start background health check loop."""
        self._running = True
        asyncio.create_task(self._health_check_loop())
        logger.info("Started connector health checks")
    
    async def stop_health_checks(self) -> None:
        """Stop health check loop."""
        self._running = False
    
    async def _health_check_loop(self) -> None:
        """Periodically check connector health."""
        while self._running:
            await asyncio.sleep(self._health_check_interval)
            await self.check_all_health()
    
    async def check_all_health(self) -> Dict[str, Tuple[bool, str]]:
        """Check health of all connectors."""
        results = {}
        
        for name, state in self._connectors.items():
            if not state.enabled:
                results[name] = (False, "Disabled")
                continue
            
            try:
                healthy, message = await state.connector.health_check()
                state.healthy = healthy
                state.last_health_check = datetime.now(timezone.utc)
                results[name] = (healthy, message)
                
                if healthy:
                    logger.debug(f"Connector '{name}' is healthy: {message}")
                else:
                    logger.warning(f"Connector '{name}' is unhealthy: {message}")
                    
            except Exception as e:
                state.healthy = False
                state.last_health_check = datetime.now(timezone.utc)
                results[name] = (False, str(e))
                logger.error(f"Health check failed for '{name}': {e}")
        
        return results
    
    async def set_user_token_and_check(self, connector_name: str, token: str) -> Tuple[bool, str]:
        """
        Set a user's token for a connector and run a health check.
        
        This is useful when a user connects their OAuth token - we want to
        immediately verify it's valid by running a health check.
        
        Returns:
            (healthy, message)
        """
        connector = self.get_connector(connector_name)
        if not connector:
            return False, f"Connector '{connector_name}' not found"
        
        # Set the token on the connector
        if hasattr(connector, "set_token"):
            connector.set_token(token)
        
        # Run health check
        try:
            healthy, message = await connector.health_check()
            state = self._connectors.get(connector_name)
            if state:
                state.healthy = healthy
                state.last_health_check = datetime.now(timezone.utc)
            return healthy, message
        except Exception as e:
            return False, f"Health check failed: {e}"
    
    async def close_all(self) -> None:
        """Close all connectors."""
        for name, state in self._connectors.items():
            try:
                await state.connector.close()
            except Exception as e:
                logger.error(f"Failed to close connector '{name}': {e}")


# -----------------------------------------------------------------------------
# Global Registry Instance
# -----------------------------------------------------------------------------

_registry: Optional[ConnectorRegistry] = None


def get_registry() -> ConnectorRegistry:
    """Get the global connector registry."""
    global _registry
    if _registry is None:
        _registry = ConnectorRegistry()
    return _registry


async def initialize_connectors() -> ConnectorRegistry:
    """
    Initialize the connector registry.

    All connector types are always registered so their tools are discoverable
    via /v1/tools even when no shared credentials are configured.  Connectors
    without a shared credential are registered with an empty api_key; they
    will still work as long as the calling user has stored their own token via
    POST /v1/tokens.
    """
    registry = get_registry()

    for conn_name, conn_class in registry.CONNECTOR_TYPES.items():
        env_key = registry.CREDENTIAL_ENV_KEYS.get(conn_name)
        shared_key = os.getenv(env_key, "") if env_key else ""

        config = ConnectorConfig(api_key=shared_key)
        connector = conn_class(config)
        await registry.register_connector_async(conn_name, connector, enabled=True)

        if shared_key:
            logger.info(f"Connector '{conn_name}' registered with shared credential")
        else:
            logger.info(
                f"Connector '{conn_name}' registered (no shared credential — "
                f"users must provide their own token via POST /v1/tokens)"
            )

    # Start health checks for all connectors (they'll check for tokens at runtime)
    await registry.start_health_checks()

    return registry


# -----------------------------------------------------------------------------
# Integration with Backend Manager
# -----------------------------------------------------------------------------

def get_connector_tools() -> List[Dict[str, Any]]:
    """Get all connector tools in a format suitable for the backend manager."""
    registry = get_registry()
    return registry.get_all_tools()


async def call_connector_tool(
    tool_name: str,
    arguments: Dict[str, Any],
) -> Tuple[bool, Any]:
    """
    Call a connector tool.
    
    This is the main interface for the backend manager to call tools.
    """
    registry = get_registry()
    return await registry.call_tool(tool_name, arguments)

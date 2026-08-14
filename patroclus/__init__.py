"""
Patroclus integration for Relay MCP gateway.

Provides scoped, time-limited authorization for AI agents accessing
tools through the Relay MCP proxy.
"""

from patroclus.client import PatroclusClient

__all__ = ["PatroclusClient"]

#!/bin/bash
# Relay MCP Server launcher
# This script runs the relay in MCP stdio mode

cd /Users/rshetty/agentic-gateway

# Activate virtual environment and run MCP server
source venv/bin/activate
exec python -m gateway.server mcp

#!/bin/bash
# Relay Startup Script

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Relay ===${NC}"
echo ""

# Check for .env file
if [ ! -f .env ]; then
    echo -e "${YELLOW}No .env file found. Creating default...${NC}"
    cat > .env << EOF
# Relay Configuration
RELAY_ENVIRONMENT=development
RELAY_SERVER__PORT=8000

# OAuth (auto-generated in dev)
RELAY_OAUTH__JWT_SECRET_KEY=$(openssl rand -hex 32)

# Security
RELAY_SECURITY__RATE_LIMIT_REQUESTS_PER_MINUTE=60
RELAY_SECURITY__AUDIT_ENABLED=true
RELAY_SECURITY__AUDIT_LOG_PATH=logs/audit.log

# Backend Credentials (set these for backend access)
# GITHUB_PERSONAL_ACCESS_TOKEN=ghp_xxx
# OPENAI_API_KEY=sk-xxx
# SLACK_BOT_TOKEN=xoxb-xxx
EOF
    echo -e "${GREEN}Created .env file with defaults${NC}"
fi

# Load environment
set -a
source .env
set +a

# Create required directories
mkdir -p logs data

# Parse arguments
MODE=${1:-http}

case $MODE in
    http|serve)
        echo -e "${GREEN}Starting HTTP server...${NC}"
        python -m gateway.server
        ;;
    mcp)
        echo -e "${GREEN}Starting MCP server (stdio mode)...${NC}"
        python -c "from gateway.server import run_mcp_server; run_mcp_server()"
        ;;
    docker)
        echo -e "${GREEN}Starting with Docker Compose...${NC}"
        docker-compose up --build
        ;;
    test)
        echo -e "${GREEN}Running tests...${NC}"
        pytest tests/ -v
        ;;
    *)
        echo -e "${RED}Unknown mode: $MODE${NC}"
        echo "Usage: $0 [http|mcp|docker|test]"
        exit 1
        ;;
esac

#!/bin/bash

# Relay Gateway Startup Script
set -e

cd "$(dirname "$0")/.."

# Load environment variables
if [ -f .env ]; then
    export $(grep -v '^#' .env | xargs)
fi

# Check if venv exists
if [ ! -d .venv ]; then
    echo "Creating virtual environment..."
    python3.11 -m venv .venv
    source .venv/bin/activate
    pip install --upgrade pip
    pip install -e ".[dev]"
else
    source .venv/bin/activate
fi

# Check if server is already running
if lsof -Pi :8000 -sTCP:LISTEN -t >/dev/null 2>&1; then
    echo "Relay gateway is already running on port 8000"
    exit 1
fi

# Start the server in the background
echo "Starting Relay gateway on port 8000..."
nohup python -m gateway.server http > server.log 2>&1 &

# Store the PID
echo $! > server.pid

# Wait a moment to check if it started successfully
sleep 3

if kill -0 $(cat server.pid) 2>/dev/null; then
    echo "✅ Relay gateway started successfully (PID: $(cat server.pid))"
    echo "📋 Logs: tail -f server.log"
    echo "🛑 Stop: kill $(cat server.pid) && rm server.pid"
    echo "🔗 Health check: curl http://localhost:8000/live"
else
    echo "❌ Failed to start Relay gateway"
    if [ -f server.log ]; then
        echo "Last few log lines:"
        tail -10 server.log
    fi
    rm -f server.pid
    exit 1
fi

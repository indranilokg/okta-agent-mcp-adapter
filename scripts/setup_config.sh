#!/bin/bash
set -e

# If CONFIG_YAML is set in environment, write it to config/config.yaml
if [ -n "$CONFIG_YAML" ]; then
    mkdir -p config
    echo "$CONFIG_YAML" > config/config.yaml
    echo "✓ Config loaded from environment variable"
else
    echo "⚠ CONFIG_YAML not set, using default config if exists"
fi

# Get PORT from Render or use default
PORT=${PORT:-8000}
echo "Starting on port: $PORT"

# IMPORTANT: Set GATEWAY_PORT BEFORE importing any Python modules
# This ensures the config loads with the correct port
export GATEWAY_PORT=$PORT

# Run uvicorn with explicit environment variable
exec uvicorn okta_agent_proxy.main:app --host 0.0.0.0 --port $PORT

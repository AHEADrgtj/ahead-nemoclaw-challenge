#!/usr/bin/env bash
# Start the bridge server. Works both inside and outside the NemoClaw sandbox.
# Usage: ./start.sh

cd "$(dirname "$0")"

# Activate venv if it exists (local dev)
if [ -f ".venv/bin/activate" ]; then
  source .venv/bin/activate
fi

# Load .env from project root if present
if [ -f "../.env" ]; then
  set -a; source ../.env; set +a
fi

# Inside a sandbox, use host.docker.internal to reach the Elixir app
if [ -z "$ELIXIR_LOG_URL" ] && [ -f "/sandbox/.nemoclaw" ] 2>/dev/null; then
  export ELIXIR_LOG_URL="http://host.docker.internal:4500/api/bridge-logs"
fi

echo "Starting NemoClaw bridge on http://0.0.0.0:8000"
echo "  NVIDIA API: ${NVIDIA_API_KEY:+configured}${NVIDIA_API_KEY:-not set}"
echo "  Log URL: ${ELIXIR_LOG_URL:-http://localhost:4500/api/bridge-logs}"
exec python3 -m uvicorn bridge_server:app --host 0.0.0.0 --port 8000

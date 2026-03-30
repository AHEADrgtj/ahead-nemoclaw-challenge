#!/usr/bin/env bash
# Start the OpenClaw skill runner.
# Works both inside the NemoClaw sandbox and locally.
#
# The sandbox blocks PyPI (egress policy) and runs Linux Python 3.11,
# so we vendor deps on the host targeting the sandbox platform.
#
# One-time setup (from HOST):
#   cd nemoclaw_agent/openclaw_skills
#   # Detect sandbox arch (aarch64 on Apple Silicon, x86_64 on Intel):
#   ARCH=$(docker exec $(docker ps -qf name=openshell-cluster) uname -m)
#   pip3 install --target vendor \
#     --platform manylinux2014_${ARCH} --python-version 3.11 \
#     --only-binary=:all: --implementation cp \
#     fastapi 'uvicorn[standard]' pydantic httpx openai pandas numpy
#   cd ../..
#   openshell sandbox upload ahead-secops nemoclaw_agent nemoclaw_agent
#
# Then inside the sandbox:
#   cd ~/nemoclaw_agent/openclaw_skills && bash start.sh

set -euo pipefail
cd "$(dirname "$0")"

# Kill any previous skill runner still holding the port (sandbox has no pkill/ps)
for pid in /proc/[0-9]*/; do
  if grep -q uvicorn "$pid/cmdline" 2>/dev/null; then
    kill -9 "$(basename "$pid")" 2>/dev/null && echo "Killed stale uvicorn (PID $(basename "$pid"))"
  fi
done

SKILL_DIR="$(pwd)"
AGENT_DIR="$(cd .. && pwd)"

# Use vendored deps (pip3 install --target vendor)
if [ -d "vendor" ]; then
  export PYTHONPATH="${SKILL_DIR}/vendor:${AGENT_DIR}:${SKILL_DIR}:${PYTHONPATH:-}"
else
  echo "ERROR: No vendor/ directory found. Install deps on the host first:"
  echo ""
  echo "  If vendor/ exists on your host, just re-upload:"
  echo "    openshell sandbox upload ahead-secops nemoclaw_agent nemoclaw_agent"
  echo ""
  echo "  If not, build it first (from host):"
  echo "    cd nemoclaw_agent/openclaw_skills"
  echo "    ARCH=\$(docker exec \$(docker ps -qf name=openshell-cluster) uname -m)"
  echo "    pip3 install --target vendor \\"
  echo "      --platform manylinux2014_\${ARCH} --python-version 3.11 \\"
  echo "      --only-binary=:all: --implementation cp \\"
  echo "      fastapi 'uvicorn[standard]' pydantic httpx openai pandas numpy"
  echo "    cd ../.."
  echo "    openshell sandbox upload ahead-secops nemoclaw_agent nemoclaw_agent"
  echo ""
  exit 1
fi

# Load .env from project root if present
if [ -f "../../.env" ]; then
  set -a; source ../../.env; set +a
fi

echo "Starting OpenClaw skill runner on http://0.0.0.0:8001"
echo "  Skills: ${SKILL_DIR}"
echo "  Sandbox: ${NEMOCLAW_SANDBOX:-${OPENSHELL_SANDBOX:-not detected}}"
exec python3 -m uvicorn skill_runner:app --host 0.0.0.0 --port 8001

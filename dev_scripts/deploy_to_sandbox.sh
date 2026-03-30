#!/usr/bin/env bash
set -euo pipefail

# Deploy OpenClaw skills + vendored deps to the NemoClaw sandbox.
#
# Vendors Python dependencies for the sandbox platform, uploads the
# nemoclaw_agent directory (skills, runner), and prints
# instructions for starting the skill runner.
#
# Prerequisites:
#   - NemoClaw installed and onboarded (sandbox "ahead-secops" exists)
#   - Docker Desktop running
#   - pip3 available on the host
#
# Usage:
#   ./dev_scripts/deploy_to_sandbox.sh              # auto-detect arch
#   ./dev_scripts/deploy_to_sandbox.sh aarch64       # explicit arch override

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SKILLS_DIR="$PROJECT_DIR/nemoclaw_agent/openclaw_skills"
SANDBOX_NAME="${NEMOCLAW_SANDBOX_NAME:-ahead-secops}"

cd "$PROJECT_DIR"

# --- Preflight checks ---
echo "==> Preflight checks"
MISSING=""
command -v nemoclaw >/dev/null 2>&1 || MISSING="$MISSING nemoclaw"
command -v openshell >/dev/null 2>&1 || MISSING="$MISSING openshell"
command -v pip3 >/dev/null 2>&1 || MISSING="$MISSING pip3"
if [ -n "$MISSING" ]; then
  echo "ERROR: Missing required commands:$MISSING"
  echo "Install NemoClaw first (see docs/nemoclaw_setup.md) and ensure pip3 is available."
  exit 1
fi
docker info >/dev/null 2>&1 || { echo "ERROR: Docker is not running."; exit 1; }
echo "    OK"

# --- Detect or accept architecture ---
if [ -n "${1:-}" ]; then
  ARCH="$1"
  echo "==> Using provided architecture: $ARCH"
else
  echo "==> Detecting sandbox architecture..."
  ARCH=$(docker exec "$(docker ps -qf name=openshell-cluster)" uname -m)
  echo "    Sandbox arch: $ARCH"
fi

# --- Vendor Python deps ---
echo "==> Vendoring Python deps for manylinux2014_${ARCH} / Python 3.11..."
rm -rf "$SKILLS_DIR/vendor"
pip3 install --target "$SKILLS_DIR/vendor" \
  --platform "manylinux2014_${ARCH}" --python-version 3.11 \
  --only-binary=:all: --implementation cp \
  fastapi 'uvicorn[standard]' pydantic httpx openai pandas numpy
echo "    Vendor built: $(du -sh "$SKILLS_DIR/vendor" | cut -f1)"

# --- Upload code to sandbox ---
echo "==> Uploading agent code to sandbox '$SANDBOX_NAME'..."
openshell sandbox upload "$SANDBOX_NAME" nemoclaw_agent nemoclaw_agent

# --- Upload vendor separately (.gitignore workaround) ---
if [ -d "$SKILLS_DIR/vendor" ]; then
  echo "==> Uploading vendor/ to sandbox..."
  cp -r "$SKILLS_DIR/vendor" /tmp/vendor-upload
  openshell sandbox upload "$SANDBOX_NAME" /tmp/vendor-upload nemoclaw_agent/openclaw_skills/vendor
  rm -rf /tmp/vendor-upload
fi

# --- Done ---
echo ""
echo "==> Deploy complete!"
echo ""
echo "    Next steps:"
echo ""
echo "    1. Start the skill runner inside the sandbox:"
echo "       nemoclaw $SANDBOX_NAME connect"
echo "       cd ~/nemoclaw_agent/openclaw_skills && bash start.sh"
echo ""
echo "    2. Port-forward (new terminal):"
echo "       openshell forward start 8001 $SANDBOX_NAME"
echo ""
echo "    3. Start the Docker stack with sandbox overlay:"
echo "       docker compose -f docker-compose.yml -f docker-compose.sandbox.yml up"
echo ""
echo "    4. (Optional) Monitor egress approvals:"
echo "       openshell term"

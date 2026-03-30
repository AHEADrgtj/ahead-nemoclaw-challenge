"""
Warmup Script

Pre-triggers outbound requests from inside the sandbox so the operator
can approve them in `openshell term` before the demo starts. Without this,
the first real skill call hits unapproved egress and the episode fails
(the openai SDK retries but eventually times out).

Run inside the sandbox after starting the skill runner:

    python3 warmup.py

Or from the host:

    nemoclaw ahead-secops connect -- python3 /sandbox/nemoclaw_agent/openclaw_skills/warmup.py

What it does:
  1. Calls https://inference.local/v1/models — warms up the inference proxy
  2. Calls http://host.docker.internal:4500/api/bridge-logs — warms up the
     bridge log endpoint (may need egress approval)
  3. Makes a minimal chat completion to inference.local — warms the LLM
     connection through the privacy router to the NVIDIA API

After running, check openshell term and approve any pending requests.
Then the demo will run without cold-start egress blocks.
"""

import os
import sys
import json
import time

# Add vendor to path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
VENDOR_DIR = os.path.join(SCRIPT_DIR, "vendor")
if os.path.isdir(VENDOR_DIR) and VENDOR_DIR not in sys.path:
    sys.path.insert(0, VENDOR_DIR)

import httpx


def warmup_inference():
    """Hit inference.local to trigger egress approval for the NVIDIA API."""
    print("  [1/3] Warming up inference.local...", end=" ", flush=True)
    try:
        # First: model list (lightweight)
        resp = httpx.get("https://inference.local/v1/models", timeout=30.0)
        print(f"models: {resp.status_code}", end=" ", flush=True)
    except Exception as e:
        print(f"models: {e}", end=" ", flush=True)

    try:
        # Then: a minimal chat completion (triggers the actual LLM connection)
        resp = httpx.post(
            "https://inference.local/v1/chat/completions",
            json={
                "model": "unused",
                "messages": [{"role": "user", "content": "Say OK"}],
                "max_tokens": 5,
                "temperature": 0,
            },
            timeout=60.0,
        )
        print(f"chat: {resp.status_code}")
    except Exception as e:
        print(f"chat: {e}")
        print("         ↳ Check openshell term and approve the NVIDIA API request, then re-run warmup")


def warmup_bridge_logs():
    """Hit the Elixir bridge log endpoint to trigger egress approval."""
    log_url = os.getenv("ELIXIR_LOG_URL", "http://host.docker.internal:4500/api/bridge-logs")
    print(f"  [2/3] Warming up bridge logs ({log_url})...", end=" ", flush=True)
    try:
        resp = httpx.post(
            log_url,
            json={
                "incident_id": "warmup",
                "log_type": "bridge_event",
                "skill": "warmup",
                "event": "warmup",
                "detail": {"source": "warmup.py"},
            },
            timeout=10.0,
        )
        print(f"{resp.status_code}")
    except Exception as e:
        print(f"{e}")
        print("         ↳ Check openshell term and approve host.docker.internal:4500, then re-run warmup")


def warmup_skill_runner():
    """Hit the local skill runner health endpoint."""
    print("  [3/3] Checking skill runner...", end=" ", flush=True)
    try:
        resp = httpx.get("http://localhost:8001/health", timeout=5.0)
        data = resp.json()
        print(f"{data.get('status', 'unknown')} (sandbox: {data.get('sandbox', '?')})")
    except Exception as e:
        print(f"not running ({e})")
        print("         ↳ Start it first: cd ~/nemoclaw_agent/openclaw_skills && bash start.sh")


if __name__ == "__main__":
    print()
    print("Sandbox Warmup")
    print("=" * 40)
    print()
    warmup_skill_runner()
    warmup_bridge_logs()
    warmup_inference()
    print()
    print("Done. If any requests are pending in openshell term,")
    print("approve them now, then re-run: python3 warmup.py")
    print()

# AHEAD SecOps Runtime — Quickstart

## Prerequisites

- Docker Desktop (macOS, Windows, or Linux)
- (Optional) NVIDIA API key from build.nvidia.com for real LLM inference

---

## Option 1: Mock Mode (no API key needed)

Uses synthetic responses for all skills. Good for testing the pipeline,
UI, and approval flow without any external dependencies.

```bash
cp .env.example .env
```

Edit `.env` and set:

```
BRIDGE_ADAPTER=mock
```

```bash
docker compose up
```

No NVIDIA key, no Python bridge needed — the Elixir app handles everything
with built-in mock responses.

---

## Option 2: HTTP Bridge with Real Inference (recommended)

The Python bridge runs in Docker alongside the Elixir app.
Skills call the NVIDIA API for real LLM inference and RAPIDS analysis.

```bash
cp .env.example .env
```

Edit `.env` and add your NVIDIA API key:

```
NVIDIA_API_KEY=nvapi-your-key-here
```

`BRIDGE_ADAPTER` defaults to `http` — no need to change it.

```bash
docker compose up
```

---

## Option 3: NemoClaw Sandbox (full agent isolation)

> Note: These setup instructions are not publicly executable at this time.

Skills run inside the NemoClaw sandbox with egress controls, credential
isolation via the privacy router, and real-time approval via `openshell term`.

### Prerequisites

- NemoClaw CLI installed
- Sandbox created and skills uploaded (see docs/nemoclaw-setup.md)

### Running

```bash
# Terminal 1: start skill runner inside sandbox
nemoclaw ahead-secops connect
cd ~/nemoclaw_agent/openclaw_skills
bash start.sh

# Terminal 2: port-forward from sandbox
openshell forward start 8001 ahead-secops --background

# Terminal 3: start the Docker stack with sandbox overlay
cp .env.example .env
docker compose -f docker-compose.yml -f docker-compose.sandbox.yml up

# Terminal 4 (optional): egress approval TUI
openshell term
```

The sandbox overlay routes the Elixir container to the host's NemoClaw
skill runner instead of the Docker bridge container. The codebase in the sandbox never needs
API keys — credentials are injected by the host runtime via the privacy router.

---

## Endpoints

| Endpoint | URL |
|----------|-----|
| Dashboard | http://localhost:4500 |
| CrowdStrike Twin | http://localhost:4242 |
| ServiceNow Twin | http://localhost:4244 |

## Running the Demo

1. Open the **CrowdStrike Twin** at http://localhost:4242
2. Pick a MITRE technique, set hostname/user, click **Trigger Detection Event**
3. Watch the **Dashboard** — the incident flows through Investigate → Plan → Approval
4. Review the remediation plan, click **Approve**
5. Watch execution progress in the bridge logs
6. Check the **ServiceNow Twin** at http://localhost:4244 for the ticket timeline

## Stopping

```bash
docker compose down
```

To also remove the database volume:

```bash
docker compose down -v
```

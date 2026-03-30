> Note: These setup instructions contain references to scripts that are not available publicly.

# NemoClaw Setup Guide (macOS)

Step-by-step guide to getting the NemoClaw sandbox running on macOS with
Docker Desktop. This gives you the full demo with egress-controlled agent
execution and the two-approval-layer story.

---

## Prerequisites

- **Docker Desktop** — running ([install](https://www.docker.com/products/docker-desktop/))
- **Node.js 22+** — `brew install node` (NemoClaw requires >=20)
- **Homebrew** — `/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"`

## 1. Install NemoClaw

```bash
cd /path/to/ahead_secops_runtime
./dev_scripts/setup_nemoclaw.sh
```

This clones NemoClaw to `/tmp/NemoClaw`, builds it, and runs `npm install -g`.

If you get a permission error during install:

```bash
cd /tmp/NemoClaw
sudo npm install -g .
```

Fix any permission issues on config directories:

```bash
sudo chown -R $(whoami) ~/.nemoclaw ~/.config/openshell
```

## 2. Run NemoClaw onboard

```bash
nemoclaw onboard
```

The wizard will:

1. **Preflight checks** — verifies Docker is running, Node.js version, ports available
2. **Gateway** — starts the OpenShell gateway (Docker container)
3. **Sandbox** — creates a sandboxed environment (name it `ahead-secops`)
4. **Inference** — choose "NVIDIA Cloud API" and pick a model
5. **OpenClaw** — sets up the agent inside the sandbox
6. **Policy presets** — when asked "Apply suggested presets (pypi, npm)?", say **Y**

### Common issues during onboard

**Port 18789 in use:**
```bash
sudo lsof -i :18789
sudo kill <pid>     # usually a stale SSH tunnel from a previous run
```

**Port 8080 in use:**
```bash
# Stop any existing OpenShell gateway
docker stop $(docker ps -q --filter "name=openshell") 2>/dev/null
```

**Permission denied on `~/.nemoclaw/` or `~/.config/openshell/`:**
```bash
sudo chown -R $(whoami) ~/.nemoclaw ~/.config/openshell
```

**"Sandbox not found" error during step 6:**
The sandbox registration got out of sync. Destroy and restart:
```bash
nemoclaw ahead-secops destroy
nemoclaw onboard
```

## 3. Verify the sandbox

```bash
nemoclaw ahead-secops status
```

Should show `Phase: Ready`.

## 4. Upload the bridge code to the sandbox

The sandbox is a clean Linux container — it doesn't have your project code
or Python dependencies. You need to upload them.

```bash
./dev_scripts/upload_to_sandbox.sh --vendor
```

## 5. Start the bridge inside the sandbox

```bash
nemoclaw ahead-secops connect
```

Inside the sandbox:

```bash
cd ~/nemoclaw_agent/openclaw_skills
bash start.sh
```

## 6. Forward the bridge port

In a **new terminal** on your Mac:

```bash
openshell forward start 8001 ahead-secops
```

## 7. Monitor egress approvals

In another terminal:

```bash
openshell term
```

This is the NemoClaw TUI that shows blocked network requests. When the
remediation skill tries to reach an unapproved external resource, the request appears
here for operator approval.

## 8. Run the demo

Open http://localhost:4500 
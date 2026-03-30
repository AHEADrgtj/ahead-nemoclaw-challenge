# SecOps Response Runtime

**Agentic incident response that replaces static SOAR playbooks with LLM reasoning — powered by NVIDIA NemoClaw, RAPIDS, CrowdStrike, Palo Alto Networks and ServiceNow.**

A detection event fires from Crowdstrike or Palo Alto Networks. RAPIDS pre-processes 47,000 host telemetry events on GPU, then a NemoClaw-sandboxed agent investigates the ranked anomalies, maps the full attack chain to MITRE ATT&CK, and proposes a tailored remediation plan. A human approves with one click. NemoClaw executes the containment — network isolation, process kill, persistence removal, credential reset — all within egress-controlled sandbox guardrails. The incident syncs to ServiceNow with a full work notes timeline. End to end, no playbook, no manual triage.

---

## The Problem

Every SOAR platform on the market runs **static playbooks**. Someone
writes the response procedure in advance, the system executes it. When the
attack doesn't match the playbook, the analyst is back to manual triage.

The gap between detection and response is where breaches happen, and
playbooks can't close it because they don't reason about the specific
incident.

## The Solution

This runtime replaces the playbook with an **agentic episode**. The model
investigates the specific incident, reasons about what it finds, and proposes
a response tailored to that threat. The human approves the reasoning, not
just the action.

- **NVIDIA NemoClaw** — sandboxed agent execution with policy-based egress controls, ensuring remediation actions can't escape the guardrails
- **NVIDIA RAPIDS** — GPU-accelerated telemetry pre-processing (47k+ events in ~180ms) before LLM reasoning
- **NVIDIA build.nvidia.com** — LLM inference for investigation analysis, remediation planning, and execution reporting
- **CrowdStrike + Palo Alto Networks** — real-time endpoint detection as the trigger source
- **ServiceNow** — ITSM ticket sync with full lifecycle tracking (create on detection, update at every phase)

+ AHEAD's runtime framework that orchestrates the multi-phase response with durable state, budget enforcement, and human approval gates

### SOAR vs Agentic Response

| | Traditional SOAR | This Runtime |
|---|---|---|
| **Response logic** | Static playbook: `if detection_type == X then action Y` | Agentic episode: model reads evidence, reasons, proposes tailored response |
| **Investigation** | Pre-scripted enrichment queries | LLM analyzes RAPIDS anomaly summary, maps full attack chain |
| **Remediation plan** | Fixed action sequence per alert type | LLM generates plan specific to this incident's findings |
| **Approval** | Approve the action (or auto-execute) | Approve the reasoning — human reviews investigation + plan before execution |
| **Adaptability** | New threat = new playbook to write | New threat = same agent, new reasoning |
| **Sandbox** | Trust the playbook (no sandbox) | NemoClaw enforces egress controls on the agent itself |

## NVIDIA Ecosystem Integration

| Component | Role |
|---|---|
| **NemoClaw** | Sandboxed agent runtime with blueprint-defined egress controls, filesystem isolation, and execution limits. Skills run inside NemoClaw's security boundary. |
| **LLM Inference (build.nvidia.com)** | Investigation analysis, remediation plan generation, and per-step execution reporting. With the `http` adapter, skills call the NVIDIA API directly (`NVIDIA_MODEL` env var). With the `openclaw` adapter, skills call `https://inference.local/v1` inside the sandbox — model/provider configured on the host via `openshell inference set`. Default model: `meta/llama-3.1-8b-instruct`. |
| **NemoClaw Blueprint** | YAML-based policy config defining allowed network egress (only NVIDIA API + CrowdStrike RTR), read-only filesystem, wall-time limits, and approval requirements. |
| **RAPIDS cuDF** | GPU-accelerated log pre-processing. Analyzes 47,000+ host telemetry events in ~180ms. Extracts process anomalies, network beaconing, lateral movement patterns, and log frequency spikes before LLM reasoning begins — reducing token usage and improving investigation precision. Falls back to pandas on CPU. |

## AHEAD Partner Integration

| Partner | Integration |
|---|---|
| **CrowdStrike** | Webhook ingestion of Falcon detection events. Real CrowdStrike alert payloads with MITRE ATT&CK technique IDs, host telemetry, and process trees. Reference environment for remediation actions. |
| **Palo Alto Networks** | Webhook ingestion of Cortex XDR alerts. Normalized to the same internal format as CrowdStrike — the investigation/plan/remediate pipeline is source-agnostic. XDR reference environment for endpoint actions. Remediation target is system-defined (not agent-chosen) based on detection source. |
| **ServiceNow** | Ticket created on detection, updated at every phase (investigating, plan ready, approved/rejected, remediated). Full work notes timeline with detection source, investigation summary, remediation target, and resolution notes. |

## Agentic Security Controls (P1–P5)

The runtime implements AHEAD's five-control agentic security framework, mapped to the [OWASP Top 10 for Agentic Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/).

| Control | What It Means | How the Runtime Implements It |
|---|---|---|
| **P1 — Authenticated Interface** | Every endpoint authenticated, default-deny ingress/egress | HMAC-SHA256 webhook validation on CrowdStrike/Palo Alto ingress. NemoClaw blueprint enforces default-deny egress — only `inference.local` is pre-approved. All other outbound traffic blocked and surfaced in `openshell term`. |
| **P2 — Capability Scoping** | Minimum-privilege per tool, execution budgets | Tiered skill permissions: investigate/plan require no approval, remediate requires human sign-off. Credential isolation via privacy router (agent never sees API keys). AHEAD runtime budgets: `max_turns`, `max_tokens`, `max_wall_ms` per expectation. Circuit breakers kill runaway episodes. |
| **P3 — Verified Execution** | Every action verified before firing | Two independent approval layers: (1) browser — analyst reviews the remediation plan, (2) NemoClaw blueprint enforces default-deny egress policy and `openshell term` requires operator approval for each new outbound host. State machine enforcement prevents skipping phases. ServiceNow work notes create an external audit trail the agent cannot modify. |
| **P4 — Integrity & Sync** | Verify data integrity at every boundary | SHA-256 skill code hashing at invocation time — stored in bridge logs, visible on the dashboard. Bridge logs capture full request/response bodies. Cryptographic random IDs (no sequential/guessable identifiers). Webhook payload normalization before processing. |
| **P5 — Access Control & Isolation** | Separate control plane from data plane | Sandbox can't push data outbound (results flow back on the caller's HTTP connection, not via agent-initiated POST). Strategies are compiled code, not database rows — can't be rewritten via data-layer exploit. Orchestrator, bridge, and NemoClaw sandbox run as separate processes with separate network surfaces. |
---

## Quick Start

> **Just want to run it?** See **[QUICKSTART.md](QUICKSTART.md)** — two
> paths (mock and OpenClaw sandbox), copy-paste blocks, no preamble.

Two primary paths:

### Mock mode (test the pipeline offline)

Uses synthetic responses — no API keys, no Python, no sandbox needed.

### OpenClaw sandbox (the full demo)

Skills run inside the NemoClaw sandbox using `https://inference.local/v1`
for real LLM inference. The sandbox's privacy router handles credentials —
no API keys inside the sandbox. Real-time bridge log events stream to the
dashboard as each remediation step executes.

Requires NemoClaw + Docker Desktop. See **[QUICKSTART.md](QUICKSTART.md)**
for the full setup and run commands, or [docs/nemoclaw-setup.md](docs/nemoclaw-setup.md)
for the detailed NemoClaw walkthrough.

**Two approval layers:**
1. **Browser** — Workflow approval gate (human reviews and approves the remediation plan)
2. **Terminal** — NemoClaw egress approval (operator approves outbound requests in `openshell term`)

### Other run options

The `http` bridge adapter and Docker full-stack mode are also available for
local development without a sandbox — see [QUICKSTART.md](QUICKSTART.md)
"Other run options" for details.

### After starting (all paths)

- **Dashboard:** http://localhost:4500
- **CrowdStrike Simulator:** http://localhost:4242
- **Palo Alto Networks Simulator** http://localhost:4243
- **ServiceNow Viewer:** http://localhost:4244
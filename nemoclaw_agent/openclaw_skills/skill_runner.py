"""
OpenClaw Skill Runner

Lightweight FastAPI server that loads OpenClaw skills from SKILL.md directories
and serves them as HTTP endpoints. Runs inside the NemoClaw sandbox.

Skills use the sandbox's https://inference.local/v1 endpoint via the openai
Python SDK. The sandbox's privacy router handles credentials and model routing.

Start inside the sandbox:
  cd ~/nemoclaw_agent/openclaw_skills
  bash start.sh

Port-forward to host:
  openshell forward start 8001 ahead-secops --background
"""

import json
import logging
import os
import sys
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import httpx
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
logger = logging.getLogger("openclaw.skill_runner")

# Suppress httpx INFO logs for inference calls (shown per-step, too noisy)
logging.getLogger("httpx").setLevel(logging.WARNING)

# Ensure skill directories are importable
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
for skill_dir in ["investigate", "plan", "remediate"]:
    skill_path = os.path.join(SCRIPT_DIR, skill_dir)
    if skill_path not in sys.path:
        sys.path.insert(0, skill_path)

# Also add the parent (nemoclaw_agent) for shared modules like rapids/
PARENT_DIR = os.path.dirname(SCRIPT_DIR)
if PARENT_DIR not in sys.path:
    sys.path.insert(0, PARENT_DIR)

# Bridge log URL — POST events here so they show in the Elixir dashboard
ELIXIR_LOG_URL = os.getenv(
    "ELIXIR_LOG_URL",
    "http://host.docker.internal:4500/api/bridge-logs",
)


async def log_event(
    event: str,
    skill: str,
    incident_id: str | None = None,
    detail: dict | None = None,
    error: str | None = None,
    duration_ms: int | None = None,
    model: str | None = None,
    tokens_prompt: int | None = None,
    tokens_completion: int | None = None,
):
    """POST a bridge event to the Elixir API (fire-and-forget)."""
    entry = {
        "incident_id": incident_id,
        "log_type": "bridge_event",
        "skill": skill,
        "event": event,
        "detail": detail,
        "error": error[:255] if error else None,
        "duration_ms": duration_ms,
        "model": model,
        "tokens_prompt": tokens_prompt,
        "tokens_completion": tokens_completion,
    }
    try:
        async with httpx.AsyncClient() as client:
            await client.post(ELIXIR_LOG_URL, json=entry, timeout=5.0)
    except Exception as e:
        logger.warning(
            f"[EGRESS BLOCKED] {skill}/{event} — sandbox denied POST to {ELIXIR_LOG_URL}. "
            f"Bridge log not delivered to orchestrator. "
            f"Reason: default-deny network policy ({e.__class__.__name__})"
        )


def _extract_incident_id(data: dict) -> str:
    return (
        data.get("id")
        or data.get("incident_id")
        or data.get("detection_id")
        or "unknown"
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("OpenClaw Skill Runner starting")
    logger.info(f"  Skills directory: {SCRIPT_DIR}")
    logger.info(f"  Bridge logs: {ELIXIR_LOG_URL}")
    logger.info(f"  Sandbox: {os.getenv('NEMOCLAW_SANDBOX', os.getenv('OPENSHELL_SANDBOX', 'unknown'))}")
    yield
    logger.info("OpenClaw Skill Runner stopping")


app = FastAPI(title="OpenClaw Skill Runner", lifespan=lifespan)


class InvestigateRequest(BaseModel):
    incident: dict
    host_logs: dict | None = None


class PlanRequest(BaseModel):
    incident: dict
    investigation: dict


class RemediateRequest(BaseModel):
    incident: dict
    plan: dict


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "openclaw-skill-runner",
        "sandbox": bool(os.getenv("NEMOCLAW_SANDBOX") or os.getenv("OPENSHELL_SANDBOX")),
        "bridge_logs": ELIXIR_LOG_URL,
    }


def _skill_response(result: dict):
    """Return 500 if the skill reported an error, 200 otherwise."""
    if result.get("status") == "error":
        return JSONResponse(status_code=500, content=result)
    return result


@app.post("/investigate")
async def investigate(req: InvestigateRequest):
    from investigate import run

    incident_id = _extract_incident_id(req.incident)

    async def on_event(event: str, detail: dict):
        await log_event(event, "investigate", incident_id, detail=detail)

    start = time.perf_counter()
    result = await run({"incident": req.incident, "host_logs": req.host_logs or {}}, on_event=on_event)
    duration = int((time.perf_counter() - start) * 1000)

    logger.info(f"/investigate completed in {duration}ms")
    return _skill_response(result)


@app.post("/plan")
async def plan(req: PlanRequest):
    from plan import run

    incident_id = _extract_incident_id(req.incident)

    async def on_event(event: str, detail: dict):
        await log_event(event, "plan", incident_id, detail=detail)

    start = time.perf_counter()
    result = await run({"incident": req.incident, "investigation": req.investigation}, on_event=on_event)
    duration = int((time.perf_counter() - start) * 1000)

    logger.info(f"/plan completed in {duration}ms")
    return _skill_response(result)


@app.post("/remediate")
async def remediate(req: RemediateRequest):
    from remediate import run

    incident_id = _extract_incident_id(req.incident)

    async def on_step(step_result: dict):
        """Called in real-time after each remediation step completes."""
        await log_event("step_executed", "remediate", incident_id, detail={
            "order": step_result.get("order"),
            "action": step_result.get("action"),
            "target": step_result.get("target"),
            "status": step_result.get("status"),
        })

    async def on_rtr_event(event: dict):
        """Called when an RTR twin call succeeds or is blocked."""
        event_name = event.get("event", "remediation_call")
        await log_event(event_name, "remediate", incident_id,
            detail={
                "step_order": event.get("step_order"),
                "action": event.get("action"),
                "target": event.get("target"),
                "url": event.get("url"),
                "status_code": event.get("status_code"),
                "response": event.get("response"),
            },
            error=event.get("error"),
            duration_ms=event.get("duration_ms"),
        )

    start = time.perf_counter()
    result = await run({"incident": req.incident, "plan": req.plan}, on_step=on_step, on_rtr_event=on_rtr_event)
    duration = int((time.perf_counter() - start) * 1000)

    logger.info(f"/remediate completed in {duration}ms")
    return _skill_response(result)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8001)

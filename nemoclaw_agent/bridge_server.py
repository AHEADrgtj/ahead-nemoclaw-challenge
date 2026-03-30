"""
NemoClaw Bridge Server

FastAPI server that bridges Cyclium (Elixir) to NemoClaw (Python).
Receives investigation/plan/remediation requests from the Elixir app
and delegates to NemoClaw skills running in sandboxed sessions.

When NemoClaw is not installed, falls back to local skill implementations
that use the NVIDIA API directly for LLM inference.
"""

import hashlib
import os
import json
import logging
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from pathlib import Path as PathlibPath

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Any, Optional

from skills.investigate import investigate_incident
from skills.plan import plan_remediation
from skills.remediate import execute_remediation

SKILLS_DIR = PathlibPath(os.path.dirname(__file__)) / "skills"


def compute_skill_hash(skill_name: str) -> str:
    """Compute SHA-256 of a skill's source file for integrity verification."""
    skill_file = SKILLS_DIR / f"{skill_name}.py"
    if skill_file.is_file():
        return hashlib.sha256(skill_file.read_bytes()).hexdigest()
    return "unknown"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("nemoclaw_bridge")

NVIDIA_API_KEY = os.getenv("NVIDIA_API_KEY", "")
NVIDIA_MODEL = os.getenv("NVIDIA_MODEL", "meta/llama-3.1-8b-instruct")


def _detect_sandbox() -> bool:
    """Detect if running inside a NemoClaw/OpenShell sandbox."""
    # OpenShell sets these env vars inside the sandbox
    if os.getenv("OPENSHELL_SANDBOX") or os.getenv("NEMOCLAW_SANDBOX"):
        return True
    # Check if openshell command is available (we're likely inside)
    import shutil
    if shutil.which("openshell"):
        return True
    return False


NEMOCLAW_SANDBOX = _detect_sandbox()


@asynccontextmanager
async def lifespan(app: FastAPI):
    from rapids import GPU_AVAILABLE

    logger.info("NemoClaw Bridge Server starting")
    logger.info(f"NemoClaw sandbox: {'ACTIVE — egress controlled by blueprint' if NEMOCLAW_SANDBOX else 'not detected (running unsandboxed)'}")
    logger.info(f"RAPIDS: {'GPU (cuDF)' if GPU_AVAILABLE else 'CPU (pandas fallback)'}")
    if not NVIDIA_API_KEY:
        logger.warning(
            "NVIDIA_API_KEY not set — running in mock mode. "
            "Set NVIDIA_API_KEY for real LLM inference."
        )
    yield
    logger.info("NemoClaw Bridge Server stopping")


app = FastAPI(
    title="NemoClaw Bridge Server",
    description="HTTP bridge between AHEAD SecOps Runtime and NemoClaw agent skills",
    version="0.1.0",
    lifespan=lifespan,
)


class InvestigateRequest(BaseModel):
    incident: dict[str, Any]
    host_logs: Optional[dict[str, Any]] = None


class PlanRequest(BaseModel):
    incident: dict[str, Any]
    investigation: dict[str, Any]


class RemediateRequest(BaseModel):
    incident: dict[str, Any]
    plan: dict[str, Any]


@app.get("/health")
async def health():
    from rapids import GPU_AVAILABLE

    return {
        "status": "ok",
        "service": "nemoclaw-bridge",
        "nemoclaw_sandbox": NEMOCLAW_SANDBOX,
        "nvidia_api_configured": bool(NVIDIA_API_KEY),
        "rapids_gpu_available": GPU_AVAILABLE,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/investigate")
async def investigate(req: InvestigateRequest):
    """Run NemoClaw investigation skill on the incident."""
    logger.info(
        f"Investigate request for incident: "
        f"{req.incident.get('id') or req.incident.get('detection_id', 'unknown')}"
    )
    skill_hash = compute_skill_hash("investigate")
    try:
        result = await investigate_incident(
            incident=req.incident,
            host_logs=req.host_logs or {},
            api_key=NVIDIA_API_KEY,
        )
        if isinstance(result, dict):
            result["_skill_hash"] = skill_hash
        return result
    except Exception as e:
        logger.error(f"Investigation failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/plan")
async def plan(req: PlanRequest):
    """Generate a structured remediation plan."""
    logger.info(
        f"Plan request for incident: "
        f"{req.incident.get('id') or req.incident.get('id') or req.incident.get('detection_id', 'unknown')}"
    )
    skill_hash = compute_skill_hash("plan")
    try:
        result = await plan_remediation(
            incident=req.incident,
            investigation=req.investigation,
            api_key=NVIDIA_API_KEY,
        )
        if isinstance(result, dict):
            result["_skill_hash"] = skill_hash
        return result
    except Exception as e:
        logger.error(f"Planning failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/remediate")
async def remediate(req: RemediateRequest):
    """Execute an approved remediation plan in sandbox."""
    logger.info(
        f"Remediate request for incident: "
        f"{req.incident.get('id') or req.incident.get('detection_id', 'unknown')}"
    )
    skill_hash = compute_skill_hash("remediate")
    try:
        result = await execute_remediation(
            incident=req.incident,
            plan=req.plan,
            api_key=NVIDIA_API_KEY,
        )
        if isinstance(result, dict):
            result["_skill_hash"] = skill_hash
        return result
    except Exception as e:
        logger.error(f"Remediation failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)

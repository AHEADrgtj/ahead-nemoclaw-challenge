"""
OpenClaw Plan Skill

Adapted from the bridge skill to use sandbox-managed inference
instead of direct NVIDIA API calls.

Entry point: run(input) -> dict
"""

import json
import logging
import time
from datetime import datetime, timezone

logger = logging.getLogger("openclaw.plan")


async def run(input: dict, on_event=None) -> dict:
    """OpenClaw skill entry point.

    Args:
        input: {incident, investigation}
        on_event: Optional async callback(event, detail) for real-time bridge log events.
    """
    incident = input.get("incident", {})
    investigation = input.get("investigation", {})

    incident_id = (
        incident.get("id")
        or incident.get("incident_id")
        or incident.get("detection_id")
        or "unknown"
    )
    skill_start = time.perf_counter()
    logger.info(f"[plan] Starting for incident {incident_id}")

    try:
        result = await _plan_with_inference(incident, investigation)
    except ImportError as e:
        duration_ms = int((time.perf_counter() - skill_start) * 1000)
        logger.error(f"[plan] Sandbox inference unavailable: {e}")
        return {
            "status": "error",
            "error": f"Sandbox inference unavailable: {e}",
            "detail": "The nemoclaw.inference module is not available. "
                      "Use BRIDGE_ADAPTER=http with bridge_server.py for direct API calls.",
            "duration_ms": duration_ms,
        }
    except Exception as e:
        duration_ms = int((time.perf_counter() - skill_start) * 1000)
        logger.error(f"[plan] Inference failed: {e}")
        return {
            "status": "error",
            "error": str(e),
            "duration_ms": duration_ms,
        }

    duration_ms = int((time.perf_counter() - skill_start) * 1000)

    if on_event:
        try:
            plan_detail = result.get("plan", {})
            await on_event("inference_complete", {
                "steps": len(plan_detail.get("steps", [])),
                "risk_level": plan_detail.get("risk_level"),
                "duration_ms": duration_ms,
            })
        except Exception:
            pass

    logger.info(f"[plan] Completed in {duration_ms}ms")

    return result


async def _plan_with_inference(incident: dict, investigation: dict) -> dict:
    """Use sandbox-managed inference via https://inference.local/v1."""
    from openai import OpenAI

    client = OpenAI(base_url="https://inference.local/v1", api_key="unused", max_retries=5, timeout=60.0)

    system_prompt = """You are a security incident response planner.
Given investigation findings, generate a structured remediation plan as JSON:
{
  "plan": {
    "title": "string",
    "risk_level": "low|medium|high|critical",
    "estimated_impact": "string",
    "steps": [
      {
        "order": int,
        "action": "network_isolate|kill_process|remove_persistence|block_ioc|credential_reset|scan_lateral",
        "target": "string",
        "detail": "string",
        "reversible": bool,
        "risk": "low|medium|high"
      }
    ]
  }
}
Order steps by urgency. Prioritize containment, then eradication, then recovery.
Generate between 4 and 12 steps. Do NOT repeat the same action+target combination.

IMPORTANT: Return ONLY valid JSON. The response must start with { and end with }."""

    user_message = f"""Incident:
{json.dumps(incident, indent=2)}

Investigation Findings:
{json.dumps(investigation, indent=2)}

Generate a remediation plan."""

    response = client.chat.completions.create(
        model="unused",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ],
        temperature=0.2,
        max_tokens=2048,
    )

    content = response.choices[0].message.content
    if "```json" in content:
        content = content.split("```json")[1].split("```")[0]
    elif "```" in content:
        content = content.split("```")[1].split("```")[0]

    result = json.loads(content)
    result["status"] = "complete"
    result = _deduplicate_plan_steps(result)
    return result


def _deduplicate_plan_steps(result: dict) -> dict:
    """Remove duplicate steps (same action+target)."""
    plan = result.get("plan", {})
    steps = plan.get("steps", [])
    if not steps:
        return result

    seen = set()
    unique = []
    for step in steps:
        key = (step.get("action", ""), step.get("target", ""))
        if key not in seen:
            seen.add(key)
            unique.append(step)

    for i, step in enumerate(unique, 1):
        step["order"] = i

    plan["steps"] = unique
    result["plan"] = plan
    return result


def _plan_mock(incident: dict, investigation: dict) -> dict:
    """Fallback mock plan."""
    hostname = (
        incident.get("device", {}).get("hostname")
        or incident.get("hostname", "UNKNOWN")
    )
    username = incident.get("user_name") or incident.get("username", "unknown")
    risk_score = investigation.get("risk_score", 75)
    risk_level = "critical" if risk_score >= 80 else "high" if risk_score >= 60 else "medium"

    return {
        "status": "complete",
        "plan": {
            "title": f"Incident Remediation — {hostname}",
            "risk_level": risk_level,
            "estimated_impact": f"User {username} will lose access for ~30 minutes during containment.",
            "steps": [
                {"order": 1, "action": "network_isolate", "target": hostname, "detail": f"Isolate {hostname} via CrowdStrike RTR.", "reversible": True, "risk": "low"},
                {"order": 2, "action": "kill_process", "target": "powershell.exe (PID 7284)", "detail": "Terminate malicious process tree.", "reversible": False, "risk": "low"},
                {"order": 3, "action": "remove_persistence", "target": "Scheduled Task: \\Microsoft\\Windows\\Maintenance\\WinSvc", "detail": "Remove scheduled task and dropped binary.", "reversible": False, "risk": "medium"},
                {"order": 4, "action": "block_ioc", "target": "185.220.101.42", "detail": "Add C2 IP to firewall and IOC blocklist.", "reversible": True, "risk": "low"},
                {"order": 5, "action": "credential_reset", "target": f"{username}@acmecorp.com", "detail": f"Force password reset for {username}.", "reversible": False, "risk": "medium"},
                {"order": 6, "action": "scan_lateral", "target": "WKSTN-043, WKSTN-044", "detail": "IOC sweep on lateral movement targets.", "reversible": True, "risk": "low"},
            ],
        },
        "planned_at": datetime.now(timezone.utc).isoformat(),
    }

"""
Plan Skill

Generates a structured remediation plan based on investigation findings.
Plans include ordered steps with risk levels and reversibility indicators.
"""

import json
import logging
import os
import time
from datetime import datetime, timezone

logger = logging.getLogger("nemoclaw.plan")

from bridge_logger import log_nvidia_api_call, log_bridge_event


async def plan_remediation(
    incident: dict, investigation: dict, api_key: str = ""
) -> dict:
    """Generate a structured remediation plan."""
    incident_id = incident.get("id") or incident.get("incident_id") or incident.get("detection_id") or "unknown"
    skill_start = time.perf_counter()

    await log_bridge_event("skill_start", "plan", incident_id)

    if api_key:
        result = await _plan_with_llm(incident, investigation, api_key, incident_id)
    else:
        await log_bridge_event("mock_fallback", "plan", incident_id,
                               detail={"reason": "no_api_key"})
        result = _plan_mock(incident, investigation)

    duration_ms = int((time.perf_counter() - skill_start) * 1000)
    await log_bridge_event("skill_end", "plan", incident_id, duration_ms=duration_ms)

    return result


async def _plan_with_llm(
    incident: dict, investigation: dict, api_key: str,
    incident_id: str | None = None,
) -> dict:
    """Use LLM to generate remediation plan."""
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
Generate between 4 and 12 steps. Do NOT repeat the same action+target combination. Each step must be unique.

IMPORTANT: Return ONLY valid JSON. No markdown, no commentary, no explanation before or after the JSON object. The response must start with { and end with }."""

    user_message = f"""Incident:
{json.dumps(incident, indent=2)}

Investigation Findings:
{json.dumps(investigation, indent=2)}

Generate a remediation plan."""

    request_body = {
        "model": os.getenv("NVIDIA_MODEL", "meta/llama-3.1-8b-instruct"),
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ],
        "temperature": 0.2,
        "max_tokens": 2048,
    }

    resp = await log_nvidia_api_call(
        request_body=request_body,
        skill="plan",
        function_name="_plan_with_llm",
        incident_id=incident_id,
        api_key=api_key,
        timeout=120.0,
    )

    if resp and resp.status_code == 200:
        try:
            content = resp.json()["choices"][0]["message"]["content"]
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0]
            elif "```" in content:
                content = content.split("```")[1].split("```")[0]
            result = json.loads(content)
            result["status"] = "complete"
            # Deduplicate steps (small models sometimes repeat)
            result = _deduplicate_plan_steps(result)
            return result
        except (json.JSONDecodeError, KeyError, IndexError) as e:
            await log_bridge_event("mock_fallback", "plan", incident_id,
                                   detail={"reason": "json_parse_error", "error": str(e)})
    else:
        status = resp.status_code if resp else "no_response"
        await log_bridge_event("mock_fallback", "plan", incident_id,
                               detail={"reason": "api_error", "status": status})

    return _plan_mock(incident, investigation)


def _deduplicate_plan_steps(result: dict) -> dict:
    """Remove duplicate steps (same action+target) from an LLM-generated plan."""
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

    # Re-number
    for i, step in enumerate(unique, 1):
        step["order"] = i

    plan["steps"] = unique
    result["plan"] = plan
    return result


def _plan_mock(incident: dict, investigation: dict) -> dict:
    """Generate a realistic remediation plan from investigation data."""
    hostname = (
        incident.get("device", {}).get("hostname")
        or incident.get("hostname", "UNKNOWN")
    )
    username = incident.get("user_name") or incident.get("username", "unknown")
    risk_score = investigation.get("risk_score", 75)

    risk_level = "critical" if risk_score >= 80 else "high" if risk_score >= 60 else "medium"

    steps = [
        {
            "order": 1,
            "action": "network_isolate",
            "target": hostname,
            "detail": (
                f"Isolate {hostname} from network via CrowdStrike RTR. "
                "Maintain sensor connectivity for continued monitoring."
            ),
            "reversible": True,
            "risk": "low",
        },
        {
            "order": 2,
            "action": "kill_process",
            "target": "powershell.exe (PID 7284) + child processes",
            "detail": (
                "Terminate the malicious PowerShell process tree spawned from "
                "WINWORD.EXE. Kill all child processes including wmic.exe."
            ),
            "reversible": False,
            "risk": "low",
        },
        {
            "order": 3,
            "action": "remove_persistence",
            "target": "Scheduled Task: \\Microsoft\\Windows\\Maintenance\\WinSvc",
            "detail": (
                "Remove the malicious scheduled task and delete the dropped "
                "binary at C:\\ProgramData\\svchost.exe. Verify no additional "
                "persistence mechanisms (registry run keys, services)."
            ),
            "reversible": False,
            "risk": "medium",
        },
        {
            "order": 4,
            "action": "block_ioc",
            "target": "185.220.101.42",
            "detail": (
                "Add C2 IP 185.220.101.42 to perimeter firewall deny list, "
                "CrowdStrike IOC blocklist, and DNS sinkhole. Block associated "
                "file hash in endpoint protection."
            ),
            "reversible": True,
            "risk": "low",
        },
        {
            "order": 5,
            "action": "credential_reset",
            "target": f"{username}@acmecorp.com",
            "detail": (
                f"Force password reset for {username}. Revoke all active "
                "sessions (Azure AD, VPN, SSO). Require MFA re-enrollment."
            ),
            "reversible": False,
            "risk": "medium",
        },
        {
            "order": 6,
            "action": "scan_lateral",
            "target": "WKSTN-043, WKSTN-044",
            "detail": (
                "Run full IOC sweep on hosts targeted by lateral movement. "
                "Check for WMI artifacts, SMB shares accessed, and dropped files. "
                "Verify no successful compromise."
            ),
            "reversible": True,
            "risk": "low",
        },
    ]

    return {
        "status": "complete",
        "plan": {
            "title": f"Incident Remediation — {hostname}",
            "risk_level": risk_level,
            "estimated_impact": (
                f"User {username} will lose access for ~30 minutes during "
                f"containment. {hostname} will be network-isolated until "
                "forensic review is complete."
            ),
            "steps": steps,
        },
        "planned_at": datetime.now(timezone.utc).isoformat(),
    }

"""
Remediate Skill

Executes approved remediation plans. When an NVIDIA API key is available,
uses LLM to generate context-aware execution reports for each step.
Otherwise, falls back to template-based mock detail.
"""

import asyncio
import json
import logging
import os
import time
from datetime import datetime, timezone

logger = logging.getLogger("nemoclaw.remediate")

from bridge_logger import log_nvidia_api_call, log_bridge_event


async def execute_remediation(
    incident: dict, plan: dict, api_key: str = ""
) -> dict:
    """Execute an approved remediation plan."""
    incident_id = incident.get("id") or incident.get("incident_id") or incident.get("detection_id") or "unknown"
    skill_start = time.perf_counter()

    await log_bridge_event("skill_start", "remediate", incident_id)

    hostname = (
        incident.get("device", {}).get("hostname")
        or incident.get("hostname", "UNKNOWN")
    )

    plan_detail = plan.get("plan", plan)
    steps = plan_detail.get("steps", [])

    # Remediation target is system-defined (injected by NemoClawClient)
    rem_target = plan.get("remediation_target", {})
    target_type = rem_target.get("type", "crowdstrike")

    results = []
    failed = 0

    for step in steps:
        logger.info(
            f"Executing step {step['order']}: {step['action']} on {step['target']}"
        )

        # Simulate execution time (real tools would take longer)
        await asyncio.sleep(0.5 + (hash(step["action"]) % 15) / 10.0)

        # Generate execution detail
        step_success = True
        if api_key:
            detail, step_success = await _execution_detail_llm(
                step, incident, plan_detail, api_key, incident_id
            )
        else:
            detail = _execution_detail_mock(step, target_type)

        step_status = "completed" if step_success else "failed"
        if not step_success:
            failed += 1

        result = {
            "order": step["order"],
            "action": step["action"],
            "target": step["target"],
            "status": step_status,
            "detail": detail,
            "executed_at": datetime.now(timezone.utc).isoformat(),
        }

        results.append(result)
        logger.info(f"Step {step['order']} {step_status}: {step['action']}")

    # Generate post-remediation summary
    if api_key:
        post_remediation = await _post_remediation_summary_llm(
            hostname, incident, results, api_key, incident_id
        )
    else:
        post_remediation = _post_remediation_summary_mock(hostname, results)

    duration_ms = int((time.perf_counter() - skill_start) * 1000)
    await log_bridge_event("skill_end", "remediate", incident_id, duration_ms=duration_ms)

    overall_status = "complete" if failed == 0 else "partial_failure"

    return {
        "status": overall_status,
        "host": hostname,
        "steps_executed": len(results),
        "steps_failed": failed,
        "results": results,
        "post_remediation": post_remediation,
        "completed_at": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# LLM-powered execution detail
# ---------------------------------------------------------------------------


async def _execution_detail_llm(
    step: dict, incident: dict, plan: dict, api_key: str,
    incident_id: str | None = None,
) -> tuple[str, bool]:
    """Use LLM to generate a context-aware execution report for one step.

    Returns (detail_text, success) where success=False when the API call fails.
    """
    hostname = (
        incident.get("device", {}).get("hostname")
        or incident.get("hostname", "UNKNOWN")
    )
    username = incident.get("user_name") or incident.get("username", "unknown")

    prompt = f"""You are a security operations automation engine reporting on a
remediation action that was just executed. Write a concise (3-5 sentence)
execution report for the following action. Be specific and technical.
Reference the actual target, host, and user. Do NOT use markdown formatting.

Action: {step['action']}
Target: {step['target']}
Host: {hostname}
User: {username}
Step detail: {step.get('detail', '')}
Plan context: {plan.get('title', 'Incident remediation')}"""

    request_body = {
        "model": os.getenv("NVIDIA_MODEL", "meta/llama-3.1-8b-instruct"),
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.3,
        "max_tokens": 300,
    }

    resp = await log_nvidia_api_call(
        request_body=request_body,
        skill="remediate",
        function_name="_execution_detail_llm",
        incident_id=incident_id,
        api_key=api_key,
        timeout=30.0,
    )

    if resp and resp.status_code == 200:
        try:
            return resp.json()["choices"][0]["message"]["content"].strip(), True
        except (KeyError, IndexError):
            pass

    # API error (403, 500, etc.) — report the failure
    status = resp.status_code if resp else "no_response"
    await log_bridge_event(
        "api_error", "remediate", incident_id,
        detail={
            "function": "_execution_detail_llm",
            "step_action": step["action"],
            "status": status,
        },
        error=f"NVIDIA API returned {status} for step {step['order']}: {step['action']}",
    )
    return f"FAILED: NVIDIA API returned {status} — unable to generate execution report for {step['action']} on {step['target']}", False


async def _post_remediation_summary_llm(
    hostname: str, incident: dict, results: list[dict], api_key: str,
    incident_id: str | None = None,
) -> dict:
    """Use LLM to generate a post-remediation assessment."""
    username = incident.get("user_name") or incident.get("username", "unknown")
    technique = incident.get("technique_id") or incident.get("technique", "unknown")
    steps_text = "\n".join(
        f"  {r['order']}. [{r['action']}] {r['target']} — {r['status']}"
        for r in results
    )

    prompt = f"""You are a security operations analyst writing a post-remediation
assessment. Given the completed remediation steps below, generate a JSON object
with these fields:
- host_status: string (e.g. "isolated", "remediated", "partially_remediated")
- threats_neutralized: int
- iocs_blocked: int
- credentials_reset: int
- lateral_movement_contained: bool
- ready_for_reintroduction: bool
- next_steps: array of 3-5 specific follow-up actions

Host: {hostname}
User: {username}
Technique: {technique}

Steps completed:
{steps_text}

IMPORTANT: Return ONLY valid JSON. No markdown, no commentary, no explanation. The response must start with {{ and end with }}."""

    request_body = {
        "model": os.getenv("NVIDIA_MODEL", "meta/llama-3.1-8b-instruct"),
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.2,
        "max_tokens": 500,
    }

    resp = await log_nvidia_api_call(
        request_body=request_body,
        skill="remediate",
        function_name="_post_remediation_summary_llm",
        incident_id=incident_id,
        api_key=api_key,
        timeout=30.0,
    )

    if resp and resp.status_code == 200:
        try:
            content = resp.json()["choices"][0]["message"]["content"].strip()
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0]
            elif "```" in content:
                content = content.split("```")[1].split("```")[0]
            return json.loads(content)
        except (json.JSONDecodeError, KeyError, IndexError):
            pass
    else:
        status = resp.status_code if resp else "no_response"
        await log_bridge_event(
            "api_error", "remediate", incident_id,
            detail={"function": "_post_remediation_summary_llm", "status": status},
            error=f"NVIDIA API returned {status} for post-remediation summary",
        )

    return _post_remediation_summary_mock(hostname, results)


# ---------------------------------------------------------------------------
# Mock fallbacks (template-based, no API needed)
# ---------------------------------------------------------------------------


def _execution_detail_mock(step: dict, target_type: str = "crowdstrike") -> str:
    """Template-based execution detail when LLM is unavailable."""
    action = step["action"]
    target = step["target"]

    platform = "CrowdStrike RTR" if target_type == "crowdstrike" else "Cortex XDR"
    agent = "Falcon sensor" if target_type == "crowdstrike" else "Cortex XDR agent"

    details = {
        "network_isolate": (
            f"Network isolation applied to {target} via {platform}. "
            f"Host is now isolated from the network. {agent} connectivity maintained. "
            f"Verified: no outbound connections except to {platform} cloud."
        ),
        "kill_process": (
            f"Process tree terminated: {target}. "
            "Killed 3 processes (powershell.exe, conhost.exe, wmic.exe). "
            "Verified: no respawn detected within 30-second monitoring window."
        ),
        "remove_persistence": (
            f"Persistence mechanism removed: {target}. "
            "Scheduled task deleted. Dropped binary quarantined and hashed. "
            "Scanned for additional persistence: registry run keys (clean), "
            "services (clean), startup folders (clean)."
        ),
        "block_ioc": (
            f"IOC blocked: {target}. "
            f"Added to {platform} IOC blocklist (global policy). "
            "DNS sinkhole entry created. Firewall rule deployed to all egress points. "
            "File hash added to prevention policy."
        ),
        "credential_reset": (
            f"Credentials reset for {target}. "
            "Password force-changed in Active Directory. "
            "All active sessions revoked (Azure AD: 3 sessions, VPN: 1 session). "
            "MFA re-enrollment required on next login."
        ),
        "scan_lateral": (
            f"IOC sweep completed on {target}. "
            "Scanned for: WMI artifacts, SMB share access logs, dropped files, "
            "scheduled tasks, registry modifications. "
            "Result: No evidence of successful compromise on scanned hosts."
        ),
    }

    return details.get(
        action, f"Action {action} executed on {target} — completed successfully."
    )


def _post_remediation_summary_mock(hostname: str, results: list[dict]) -> dict:
    """Template-based post-remediation summary."""
    return {
        "host_status": "isolated",
        "threats_neutralized": sum(
            1
            for r in results
            if r["action"] in ["kill_process", "remove_persistence", "block_ioc"]
        ),
        "iocs_blocked": sum(1 for r in results if r["action"] == "block_ioc"),
        "credentials_reset": sum(
            1 for r in results if r["action"] == "credential_reset"
        ),
        "lateral_movement_contained": any(
            r["action"] == "scan_lateral" for r in results
        ),
        "ready_for_reintroduction": False,
        "next_steps": [
            f"Complete forensic imaging of {hostname} before un-isolating",
            "Verify IOC sweep results on adjacent hosts show no compromise",
            "Schedule security awareness debrief with affected user",
            "Update detection rules based on observed TTPs",
            "File threat intelligence report for the observed C2 infrastructure",
        ],
    }

"""
OpenClaw Remediate Skill

Adapted from the bridge skill to use sandbox-managed inference
instead of direct NVIDIA API calls. When inference fails (403, timeout),
individual steps are marked as failed rather than falling back to mock.

Entry point: run(input) -> dict
"""

import asyncio
import json
import logging
import os
import time
from datetime import datetime, timezone

import httpx

logger = logging.getLogger("openclaw.remediate")

# ---------- Remediation target (system-defined) ----------

# Default CrowdStrike RTR config — overridden at runtime by remediation_target
# injected from the Elixir layer via RemediationTarget.for_incident/1.
_DEFAULT_TWIN_URL = os.getenv("RTR_TWIN_URL", "http://host.docker.internal:4242")
_DEFAULT_TWIN_TOKEN = os.getenv("RTR_TWIN_TOKEN", "secops-rtr-twin-demo")

_DEFAULT_ENDPOINTS = {
    "network_isolate": "/api/rtr/containment/entities/hosts/actions/v2",
    "kill_process": "/api/rtr/batch-execute-command",
    "remove_persistence": "/api/rtr/batch-execute-command",
    "block_ioc": "/api/rtr/ioc/entities/indicators/v1",
    "credential_reset": "/api/rtr/batch-execute-command",
    "scan_lateral": "/api/rtr/batch-execute-command",
}


def _is_sandbox() -> bool:
    """Detect if running inside a NemoClaw/OpenShell sandbox."""
    return bool(os.getenv("OPENSHELL_SANDBOX") or os.getenv("NEMOCLAW_SANDBOX"))


def _rewrite_for_sandbox(url: str) -> str:
    """Inside the sandbox, localhost means the container — rewrite to host gateway."""
    if _is_sandbox():
        return url.replace("localhost", "host.docker.internal").replace("127.0.0.1", "host.docker.internal")
    return url


def _resolve_target(plan: dict) -> tuple[str, str, dict]:
    """Resolve remediation target from plan (system-injected).

    Returns (target_type, base_url, endpoints_map).
    The agent NEVER chooses the target — it receives exactly one.
    """
    rem_target = plan.get("remediation_target", {})
    target_type = rem_target.get("type", "crowdstrike")
    base_url = rem_target.get("url", _DEFAULT_TWIN_URL)
    endpoints = rem_target.get("endpoints", _DEFAULT_ENDPOINTS)
    # Inside the sandbox, localhost is the container — rewrite to host gateway
    base_url = _rewrite_for_sandbox(base_url)
    return target_type, base_url, endpoints


async def _call_remediation_target(
    action: str, target: str, incident: dict, step_order: int,
    base_url: str, endpoints: dict, target_type: str,
    on_rtr_event=None,
) -> dict | None:
    """Call the remediation target twin API (CrowdStrike RTR or Palo Alto XDR).

    This call is intentionally blocked by the sandbox egress policy, causing it
    to surface in `openshell term` for operator approval. Returns the twin's
    response on success, or None if the call fails or is denied.
    """
    endpoint = endpoints.get(action)
    if not endpoint:
        return None

    device_id = (
        incident.get("device", {}).get("device_id")
        or incident.get("hostname", "unknown")
    )

    url = f"{base_url}{endpoint}"
    headers = {
        "X-Twin-Caller": "nemoclaw-remediate",
        "X-Twin-Token": _DEFAULT_TWIN_TOKEN,
    }

    # Build body with both CrowdStrike and Palo Alto field names
    body = {
        "device_id": device_id,
        "endpoint_id": device_id,
        "command_string": f"{action} {target}",
        "script_uid": f"{action} {target}",
        "type": "ipv4" if action == "block_ioc" else "command",
        "value": target,
        "file_path": target if action in ("block_ioc", "quarantine_file") else None,
        "process_name": target if action == "kill_process" else None,
    }

    platform = "CrowdStrike RTR" if target_type == "crowdstrike" else "Cortex XDR"

    start = time.perf_counter()
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(url, json=body, headers=headers)
            resp.raise_for_status()
            result = resp.json()
            duration_ms = int((time.perf_counter() - start) * 1000)

            if on_rtr_event:
                await on_rtr_event({
                    "event": "remediation_call",
                    "step_order": step_order,
                    "action": action,
                    "target": target,
                    "url": url,
                    "target_type": target_type,
                    "status_code": resp.status_code,
                    "response": result,
                    "duration_ms": duration_ms,
                })

            return result
    except Exception as e:
        duration_ms = int((time.perf_counter() - start) * 1000)
        error_msg = str(e)
        status_code = getattr(getattr(e, "response", None), "status_code", None)
        logger.warning(f"{platform} call failed for {action}: {e}")

        if on_rtr_event:
            await on_rtr_event({
                "event": "egress_blocked",
                "step_order": step_order,
                "action": action,
                "target": target,
                "url": url,
                "target_type": target_type,
                "status_code": status_code,
                "error": error_msg[:255],
                "duration_ms": duration_ms,
            })

        return None


async def run(input: dict, on_step=None, on_rtr_event=None) -> dict:
    """OpenClaw skill entry point.

    Args:
        input: {incident, plan}
        on_step: Optional async callback(step_result) called after each step completes.
                 Used by the skill runner to POST real-time bridge log events.
        on_rtr_event: Optional async callback(event_dict) called on RTR twin call
                      success or failure. Surfaces RTR results in the bridge activity log.
    """
    incident = input.get("incident", {})
    plan = input.get("plan", {})

    incident_id = (
        incident.get("id")
        or incident.get("incident_id")
        or incident.get("detection_id")
        or "unknown"
    )
    skill_start = time.perf_counter()
    logger.info(f"[remediate] Starting for incident {incident_id}")

    hostname = (
        incident.get("device", {}).get("hostname")
        or incident.get("hostname", "UNKNOWN")
    )

    # Resolve remediation target (system-defined, not agent-chosen)
    target_type, base_url, endpoints = _resolve_target(plan)
    platform = "CrowdStrike RTR" if target_type == "crowdstrike" else "Cortex XDR"
    logger.info(f"[remediate] Remediation target: {platform} at {base_url}")

    # Fail early if sandbox inference endpoint is not reachable
    try:
        from openai import OpenAI
        _client = OpenAI(base_url="https://inference.local/v1", api_key="unused", max_retries=5, timeout=30.0)
    except ImportError as e:
        duration_ms = int((time.perf_counter() - skill_start) * 1000)
        logger.error(f"[remediate] OpenAI SDK not available: {e}")
        return {
            "status": "error",
            "error": f"OpenAI SDK not available: {e}",
            "host": hostname,
            "steps_executed": 0,
            "steps_failed": 0,
            "results": [],
            "duration_ms": duration_ms,
        }

    plan_detail = plan.get("plan", plan)
    steps = plan_detail.get("steps", [])

    results = []
    failed = 0

    for step in steps:
        logger.info(f"Executing step {step['order']}: {step['action']} on {step['target']}")

        # Simulate execution time
        await asyncio.sleep(0.5 + (hash(step["action"]) % 15) / 10.0)

        # Call remediation target (blocked by sandbox egress → shows in openshell term)
        rtr_result = await _call_remediation_target(
            step["action"], step["target"], incident, step["order"],
            base_url, endpoints, target_type, on_rtr_event
        )

        # If target call was denied/failed, stop remediation — the operator
        # either denied the egress request or the twin is unreachable.
        if rtr_result is None:
            step_result = {
                "order": step["order"],
                "action": step["action"],
                "target": step["target"],
                "status": "blocked",
                "detail": f"{platform} call for {step['action']} was denied or failed. "
                          "Remediation halted — operator may need to approve egress in openshell term.",
                "rtr_response": None,
                "executed_at": datetime.now(timezone.utc).isoformat(),
            }
            results.append(step_result)
            failed += 1

            if on_step:
                try:
                    await on_step(step_result)
                except Exception:
                    pass

            logger.warning(f"Step {step['order']} blocked: {platform} {step['action']} denied — halting remediation")
            break

        detail, step_success = await _execution_detail(step, incident, plan_detail)
        step_status = "completed" if step_success else "failed"
        if not step_success:
            failed += 1

        step_result = {
            "order": step["order"],
            "action": step["action"],
            "target": step["target"],
            "status": step_status,
            "detail": detail,
            "rtr_response": rtr_result,
            "executed_at": datetime.now(timezone.utc).isoformat(),
        }
        results.append(step_result)

        logger.info(f"Step {step['order']} {step_status}: {step['action']}")

        if on_step:
            try:
                await on_step(step_result)
            except Exception:
                pass  # don't let logging failures break remediation

    # Post-remediation summary
    try:
        post_remediation = await _post_remediation_summary(hostname, incident, results)
    except Exception:
        post_remediation = _post_remediation_summary_mock(hostname, results)

    duration_ms = int((time.perf_counter() - skill_start) * 1000)
    overall_status = "complete" if failed == 0 else "partial_failure"
    logger.info(f"[remediate] Completed in {duration_ms}ms — {failed} step(s) failed")

    return {
        "status": overall_status,
        "host": hostname,
        "steps_executed": len(results),
        "steps_failed": failed,
        "results": results,
        "post_remediation": post_remediation,
        "completed_at": datetime.now(timezone.utc).isoformat(),
    }


async def _execution_detail(
    step: dict, incident: dict, plan: dict
) -> tuple[str, bool]:
    """Generate execution detail via sandbox inference. Returns (detail, success)."""
    try:
        from openai import OpenAI

        client = OpenAI(base_url="https://inference.local/v1", api_key="unused", max_retries=5, timeout=30.0)

        hostname = incident.get("hostname", "UNKNOWN")
        username = incident.get("user_name") or incident.get("username", "unknown")

        prompt = f"""You are a security operations automation engine reporting on a
remediation action that was just executed. Write a concise (3-5 sentence)
execution report. Be specific and technical.

Action: {step['action']}
Target: {step['target']}
Host: {hostname}
User: {username}
Step detail: {step.get('detail', '')}
Plan context: {plan.get('title', 'Incident remediation')}"""

        response = client.chat.completions.create(
            model="unused",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=300,
            temperature=0.3,
        )

        return response.choices[0].message.content.strip(), True

    except Exception as e:
        logger.error(f"Inference failed for step {step['order']}: {e}")
        return (
            f"FAILED: Inference error — unable to generate execution report "
            f"for {step['action']} on {step['target']}: {e}",
            False,
        )


async def _post_remediation_summary(
    hostname: str, incident: dict, results: list[dict]
) -> dict:
    """Generate post-remediation assessment via sandbox inference."""
    from openai import OpenAI

    client = OpenAI(base_url="https://inference.local/v1", api_key="unused", max_retries=5, timeout=30.0)

    username = incident.get("user_name") or incident.get("username", "unknown")
    technique = incident.get("technique_id") or incident.get("technique", "unknown")
    steps_text = "\n".join(
        f"  {r['order']}. [{r['action']}] {r['target']} — {r['status']}"
        for r in results
    )

    prompt = f"""You are a security operations analyst writing a post-remediation
assessment. Given the remediation steps below, generate a JSON object with:
- host_status: string
- threats_neutralized: int
- iocs_blocked: int
- credentials_reset: int
- lateral_movement_contained: bool
- ready_for_reintroduction: bool
- next_steps: array of 3-5 specific follow-up actions

Host: {hostname}
User: {username}
Technique: {technique}

Steps:
{steps_text}

IMPORTANT: Return ONLY valid JSON. The response must start with {{ and end with }}."""

    response = client.chat.completions.create(
        model="unused",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=500,
        temperature=0.2,
    )

    content = response.choices[0].message.content.strip()
    if "```json" in content:
        content = content.split("```json")[1].split("```")[0]
    elif "```" in content:
        content = content.split("```")[1].split("```")[0]
    return json.loads(content)


def _post_remediation_summary_mock(hostname: str, results: list[dict]) -> dict:
    """Fallback post-remediation summary."""
    return {
        "host_status": "isolated",
        "threats_neutralized": sum(
            1 for r in results
            if r["action"] in ["kill_process", "remove_persistence", "block_ioc"]
            and r["status"] == "completed"
        ),
        "iocs_blocked": sum(
            1 for r in results if r["action"] == "block_ioc" and r["status"] == "completed"
        ),
        "credentials_reset": sum(
            1 for r in results if r["action"] == "credential_reset" and r["status"] == "completed"
        ),
        "lateral_movement_contained": any(
            r["action"] == "scan_lateral" and r["status"] == "completed" for r in results
        ),
        "ready_for_reintroduction": False,
        "next_steps": [
            f"Complete forensic imaging of {hostname} before un-isolating",
            "Verify IOC sweep results on adjacent hosts",
            "Schedule security awareness debrief with affected user",
        ],
    }

"""
OpenClaw Investigate Skill

Adapted from the bridge skill to use sandbox-managed inference
instead of direct NVIDIA API calls.

Entry point: run(input) -> dict
"""

import json
import logging
import time
from datetime import datetime, timezone

logger = logging.getLogger("openclaw.investigate")


async def run(input: dict, on_event=None) -> dict:
    """OpenClaw skill entry point.

    Args:
        input: {incident, host_logs}
        on_event: Optional async callback(event, detail) for real-time bridge log events.
    """
    incident = input.get("incident", {})
    host_logs = input.get("host_logs", {})

    incident_id = (
        incident.get("id")
        or incident.get("incident_id")
        or incident.get("detection_id")
        or "unknown"
    )
    skill_start = time.perf_counter()
    logger.info(f"[investigate] Starting for incident {incident_id}")

    # Step 1: RAPIDS pre-processing
    try:
        from rapids import process_telemetry
        rapids_summary = process_telemetry(host_logs or {}, incident=incident)
    except ImportError:
        logger.warning("RAPIDS not available in skill directory, using empty summary")
        rapids_summary = {
            "total_events_processed": 0,
            "anomaly_count": 0,
            "processing_time_ms": 0,
            "gpu_accelerated": False,
            "anomalies": [],
            "top_indicators": [],
        }

    if on_event:
        try:
            await on_event("rapids_complete", {
                "events": rapids_summary.get("total_events_processed"),
                "anomalies": rapids_summary.get("anomaly_count"),
                "processing_ms": rapids_summary.get("processing_time_ms"),
                "gpu": rapids_summary.get("gpu_accelerated"),
            })
        except Exception:
            pass

    # Step 2: LLM reasoning via sandbox inference
    try:
        result = await _investigate_with_inference(incident, rapids_summary)
    except ImportError as e:
        duration_ms = int((time.perf_counter() - skill_start) * 1000)
        logger.error(f"[investigate] OpenAI SDK not available: {e}")
        return {
            "status": "error",
            "error": f"OpenAI SDK not available: {e}",
            "detail": "The openai package is required for sandbox inference. "
                      "Vendor it with: pip3 install --target vendor openai",
            "rapids_summary": rapids_summary,
            "duration_ms": duration_ms,
        }
    except Exception as e:
        duration_ms = int((time.perf_counter() - skill_start) * 1000)
        logger.error(f"[investigate] Inference failed: {e}")
        return {
            "status": "error",
            "error": str(e),
            "rapids_summary": rapids_summary,
            "duration_ms": duration_ms,
        }

    result["rapids_summary"] = rapids_summary

    duration_ms = int((time.perf_counter() - skill_start) * 1000)

    if on_event:
        try:
            await on_event("inference_complete", {
                "analysis_engine": result.get("analysis_engine", "unknown"),
                "risk_score": result.get("risk_score"),
                "findings_count": len(result.get("findings", [])),
                "duration_ms": duration_ms,
            })
        except Exception:
            pass

    logger.info(f"[investigate] Completed in {duration_ms}ms")

    return result


async def _investigate_with_inference(incident: dict, rapids_summary: dict) -> dict:
    """Use sandbox-managed inference via https://inference.local/v1."""
    from openai import OpenAI

    client = OpenAI(base_url="https://inference.local/v1", api_key="unused", max_retries=5, timeout=120.0)

    event_count = rapids_summary.get("total_events_processed", 0)
    anomaly_count = rapids_summary.get("anomaly_count", 0)
    top_indicators = rapids_summary.get("top_indicators", [])
    indicators_text = "\n".join(f"  - {ind}" for ind in top_indicators)
    anomalies_brief = json.dumps(rapids_summary.get("anomalies", [])[:10], indent=2)

    system_prompt = f"""You are a senior security analyst performing incident investigation.
You have been provided with RAPIDS GPU-accelerated anomaly analysis of {event_count:,} host
telemetry events. The pre-processing identified {anomaly_count} anomalies ranked by severity.

Work from the ranked indicators below — do NOT re-scan raw logs. Focus on the highest-confidence
signals and produce a structured findings summary.

Top indicators identified by RAPIDS:
{indicators_text}

Return a structured JSON response with:
- findings: array of {{type: string, detail: string, severity: "low"|"medium"|"high"|"critical", evidence: string[]}}
  IMPORTANT: each item in "evidence" MUST be a plain string, NOT an object. Example: ["Process: powershell.exe spawned from WINWORD.EXE", "Destination: 185.220.101.42:443"]
- timeline: array of {{time: string, event: string}}
- mitre_mapping: {{technique: string, tactics: string[], sub_techniques: string[]}}
- risk_score: integer 0-100

IMPORTANT: Return ONLY valid JSON. No markdown, no commentary. The response must start with {{ and end with }}."""

    user_message = f"""Incident Detection:
{json.dumps(incident, indent=2)}

RAPIDS Anomaly Analysis ({anomaly_count} anomalies from {event_count:,} events):
{anomalies_brief}

Affected assets: {rapids_summary.get('top_talkers', {}).get('dest_ips', [])}

Analyze these findings and return structured JSON."""

    response = client.chat.completions.create(
        model="unused",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ],
        temperature=0.2,
        max_tokens=4096,
    )

    content = response.choices[0].message.content
    if "```json" in content:
        content = content.split("```json")[1].split("```")[0]
    elif "```" in content:
        content = content.split("```")[1].split("```")[0]

    result = json.loads(content)
    result["status"] = "complete"
    result["analysis_engine"] = "openclaw-sandbox"
    return result


def _investigate_mock(incident: dict, rapids_summary: dict) -> dict:
    """Fallback mock investigation."""
    hostname = (
        incident.get("device", {}).get("hostname")
        or incident.get("hostname", "UNKNOWN")
    )
    username = incident.get("user_name") or incident.get("username", "unknown")
    technique = incident.get("technique_id", "T1059.001")

    return {
        "status": "complete",
        "analysis_engine": "openclaw-mock",
        "findings": [
            {
                "type": "process_execution",
                "detail": f"Suspicious PowerShell execution with encoded command on {hostname}",
                "severity": "high",
                "evidence": [
                    "Process: powershell.exe -EncodedCommand <base64>",
                    f"Parent: WINWORD.EXE (PID 4812)",
                    f"User: {username}",
                ],
            },
            {
                "type": "network_activity",
                "detail": "Outbound C2 communication to known malicious infrastructure",
                "severity": "critical",
                "evidence": [
                    "Destination: 185.220.101.42:443 (HTTPS)",
                    "Beacon interval consistent with Cobalt Strike default (60s jitter)",
                ],
            },
        ],
        "timeline": [
            {"time": "T-10:00", "event": f"User {username} opens macro-enabled document"},
            {"time": "T-09:38", "event": "WINWORD.EXE spawns powershell.exe with encoded command"},
            {"time": "T-09:35", "event": "C2 beacon established to 185.220.101.42:443"},
        ],
        "mitre_mapping": {
            "technique": technique,
            "tactics": ["execution", "persistence", "command-and-control"],
            "sub_techniques": ["T1059.001", "T1053.005", "T1071.001"],
        },
        "risk_score": 92,
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
    }

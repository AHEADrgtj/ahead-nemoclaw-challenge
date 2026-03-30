"""
Investigation Skill

Analyzes host logs, process trees, and network activity to determine
the scope and severity of a detected security incident.

Flow:
1. RAPIDS pre-processes raw telemetry → ranked anomaly summary
2. LLM (or mock) reasons about the summary → structured findings

When NVIDIA_API_KEY is available, uses LLM for intelligent analysis.
Otherwise, returns structured mock analysis based on the incident data.
"""

import json
import os
import time
import logging
from datetime import datetime, timezone

logger = logging.getLogger("nemoclaw.investigate")

from rapids import process_telemetry
from bridge_logger import log_nvidia_api_call, log_bridge_event


async def investigate_incident(
    incident: dict, host_logs: dict, api_key: str = ""
) -> dict:
    """Analyze an incident using RAPIDS pre-processing + LLM reasoning."""
    incident_id = incident.get("id") or incident.get("incident_id") or incident.get("detection_id") or "unknown"
    skill_start = time.perf_counter()

    await log_bridge_event("skill_start", "investigate", incident_id)

    # Step 1: RAPIDS pre-processing
    rapids_summary = process_telemetry(host_logs or {}, incident=incident)

    await log_bridge_event("rapids_complete", "investigate", incident_id, detail={
        "events": rapids_summary.get("total_events_processed"),
        "anomalies": rapids_summary.get("anomaly_count"),
        "processing_ms": rapids_summary.get("processing_time_ms"),
        "gpu": rapids_summary.get("gpu_accelerated"),
    })

    # Step 2: LLM reasoning
    if api_key:
        result = await _investigate_with_llm(
            incident, host_logs, api_key, rapids_summary, incident_id
        )
    else:
        await log_bridge_event("mock_fallback", "investigate", incident_id,
                               detail={"reason": "no_api_key"})
        result = _investigate_mock(incident, host_logs, rapids_summary)

    result["rapids_summary"] = rapids_summary

    duration_ms = int((time.perf_counter() - skill_start) * 1000)
    await log_bridge_event("skill_end", "investigate", incident_id, duration_ms=duration_ms)

    return result


async def _investigate_with_llm(
    incident: dict, host_logs: dict, api_key: str, rapids_summary: dict,
    incident_id: str | None = None,
) -> dict:
    """Use LLM to analyze the incident, informed by RAPIDS pre-processing."""
    event_count = rapids_summary.get("total_events_processed", 0)
    anomaly_count = rapids_summary.get("anomaly_count", 0)
    top_indicators = rapids_summary.get("top_indicators", [])
    indicators_text = "\n".join(f"  - {ind}" for ind in top_indicators)

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

IMPORTANT: Return ONLY valid JSON. No markdown, no commentary, no explanation before or after the JSON object. The response must start with {{ and end with }}."""

    anomalies_brief = json.dumps(rapids_summary.get("anomalies", [])[:10], indent=2)

    user_message = f"""Incident Detection:
{json.dumps(incident, indent=2)}

RAPIDS Anomaly Analysis ({anomaly_count} anomalies from {event_count:,} events):
{anomalies_brief}

Affected assets: {rapids_summary.get('top_talkers', {}).get('dest_ips', [])}

Analyze these findings and return structured JSON."""

    request_body = {
        "model": os.getenv("NVIDIA_MODEL", "meta/llama-3.1-8b-instruct"),
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ],
        "temperature": 0.2,
        "max_tokens": 4096,
    }

    resp = await log_nvidia_api_call(
        request_body=request_body,
        skill="investigate",
        function_name="_investigate_with_llm",
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
            result["analysis_engine"] = request_body["model"]
            return result
        except (json.JSONDecodeError, KeyError, IndexError) as e:
            logger.warning(f"Failed to parse NVIDIA response: {e}")
            await log_bridge_event("mock_fallback", "investigate", incident_id,
                                   detail={"reason": "json_parse_error", "error": str(e)})
    else:
        status = resp.status_code if resp else "no_response"
        await log_bridge_event("mock_fallback", "investigate", incident_id,
                               detail={"reason": "api_error", "status": status})

    return _investigate_mock(incident, host_logs, rapids_summary)


def _investigate_mock(
    incident: dict, host_logs: dict, rapids_summary: dict
) -> dict:
    """Generate realistic investigation results from incident data."""
    hostname = (
        incident.get("device", {}).get("hostname")
        or incident.get("hostname", "UNKNOWN")
    )
    username = incident.get("user_name") or incident.get("username", "unknown")
    technique = incident.get("technique_id", "T1059.001")
    now = datetime.now(timezone.utc)

    findings = [
        {
            "type": "process_execution",
            "detail": f"Suspicious PowerShell execution with encoded command on {hostname}",
            "severity": "high",
            "evidence": [
                "Process: powershell.exe -EncodedCommand <base64>",
                f"Parent: {incident.get('parent_process_name', 'WINWORD.EXE')} (PID {incident.get('parent_process_id', '4812')})",
                f"User: {username}",
                "Command matches known fileless malware delivery pattern",
            ],
        },
        {
            "type": "network_activity",
            "detail": "Outbound C2 communication to known malicious infrastructure",
            "severity": "critical",
            "evidence": [
                "Destination: 185.220.101.42:443 (HTTPS)",
                "DNS resolution via DoH — corporate DNS bypassed",
                "Beacon interval consistent with Cobalt Strike default (60s jitter)",
                "TLS JA3 fingerprint matches known C2 framework",
            ],
        },
        {
            "type": "persistence",
            "detail": "Scheduled task created for persistent access",
            "severity": "high",
            "evidence": [
                "Task: \\Microsoft\\Windows\\Maintenance\\WinSvc",
                "Action: C:\\ProgramData\\svchost.exe -k netsvcs",
                "Trigger: At logon of any user (SYSTEM context)",
                "Binary not in known-good baseline — SHA256 flagged",
            ],
        },
        {
            "type": "lateral_movement",
            "detail": "WMI-based lateral movement attempt to adjacent host",
            "severity": "high",
            "evidence": [
                "Target: WKSTN-043 via WMI (port 135)",
                f"Source credentials: {username}",
                "Remote process creation attempted via wmic.exe",
                "Activity consistent with MITRE T1047 (WMI)",
            ],
        },
    ]

    timeline = [
        {"time": "T-10:00", "event": f"User {username} opens macro-enabled document from Downloads"},
        {"time": "T-09:38", "event": "WINWORD.EXE spawns powershell.exe with encoded command"},
        {"time": "T-09:37", "event": "PowerShell decodes and executes downloader stage"},
        {"time": "T-09:35", "event": "C2 beacon established to 185.220.101.42:443"},
        {"time": "T-08:00", "event": "Dropped binary written to C:\\ProgramData\\svchost.exe"},
        {"time": "T-07:55", "event": "Scheduled task created for persistence"},
        {"time": "T-06:30", "event": "WMI lateral movement attempted to WKSTN-043"},
        {"time": "T-04:00", "event": "Persisted binary establishes independent C2 channel"},
    ]

    return {
        "status": "complete",
        "analysis_engine": "nemoclaw-mock",
        "findings": findings,
        "timeline": timeline,
        "mitre_mapping": {
            "technique": technique,
            "tactics": ["execution", "persistence", "command-and-control", "lateral-movement"],
            "sub_techniques": ["T1059.001", "T1053.005", "T1071.001", "T1047"],
        },
        "risk_score": 92,
        "iocs": [
            {"type": "ip", "value": "185.220.101.42", "context": "C2 server"},
            {"type": "hash", "value": "a3f2d4e6b8c1d3e5f7a9b2c4d6e8f0a1b3c5d7e9f1a2b4c6d8e0f2a4b6c891", "context": "Dropped binary"},
            {"type": "file", "value": "C:\\ProgramData\\svchost.exe", "context": "Persistence payload"},
        ],
        "affected_hosts": [hostname, "WKSTN-043"],
        "analyzed_at": now.isoformat(),
    }

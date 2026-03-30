"""
Bridge Logger

Structured logging for NVIDIA API calls and NemoClaw bridge events.
Writes to both a daily JSONL file and the Elixir API (Postgres).

Two entry points:
  - log_nvidia_api_call() — wraps an httpx POST to NVIDIA, captures req/res
  - log_bridge_event()    — logs a bridge application event (skill start/end, etc.)
"""

import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

logger = logging.getLogger("nemoclaw.bridge_logger")

ELIXIR_LOG_URL = os.getenv("ELIXIR_LOG_URL", "http://localhost:4500/api/bridge-logs")
LOG_DIR = Path(os.getenv("BRIDGE_LOG_DIR", os.path.join(os.path.dirname(__file__), "..", "logs", "bridge")))
NVIDIA_API_BASE = os.getenv("NVIDIA_API_BASE", "https://integrate.api.nvidia.com/v1")
NVIDIA_API_URL = f"{NVIDIA_API_BASE}/chat/completions"


def _ensure_log_dir():
    LOG_DIR.mkdir(parents=True, exist_ok=True)


def _log_file_path():
    return LOG_DIR / f"{datetime.now(timezone.utc).strftime('%Y-%m-%d')}.jsonl"


def _write_to_file(entry: dict):
    """Append a log entry to the daily JSONL file."""
    try:
        _ensure_log_dir()
        with open(_log_file_path(), "a") as f:
            f.write(json.dumps(entry, default=str) + "\n")
    except Exception as e:
        logger.warning(f"Failed to write log file: {e}")


async def _post_to_elixir(entry: dict):
    """POST log entry to the Elixir API (fire-and-forget)."""
    try:
        async with httpx.AsyncClient() as client:
            await client.post(
                ELIXIR_LOG_URL,
                json=entry,
                timeout=5.0,
            )
    except Exception as e:
        skill = entry.get("skill", "?")
        event = entry.get("event", "?")
        logger.warning(
            f"[EGRESS BLOCKED] {skill}/{event} — sandbox denied POST to {ELIXIR_LOG_URL}. "
            f"Bridge log not delivered to orchestrator. "
            f"Reason: default-deny network policy ({e.__class__.__name__})"
        )


async def log_nvidia_api_call(
    request_body: dict,
    skill: str,
    function_name: str,
    incident_id: str | None = None,
    api_key: str = "",
    timeout: float = 120.0,
) -> httpx.Response | None:
    """
    Make an NVIDIA API call and log the request/response.

    Returns the httpx Response on success, None on failure.
    The caller is responsible for parsing the response.
    """
    start = time.perf_counter()
    response = None
    error_msg = None
    status_code = None
    response_json = None
    tokens_prompt = None
    tokens_completion = None

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                NVIDIA_API_URL,
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json=request_body,
                timeout=timeout,
            )
            status_code = response.status_code

            try:
                response_json = response.json()
                # Extract token usage if available
                usage = response_json.get("usage", {})
                tokens_prompt = usage.get("prompt_tokens")
                tokens_completion = usage.get("completion_tokens")
            except Exception:
                response_json = {"raw": response.text[:2000]}

    except Exception as e:
        error_msg = str(e)
        logger.warning(f"NVIDIA API call failed ({function_name}): {e}")

    duration_ms = int((time.perf_counter() - start) * 1000)

    # Build log entry
    entry = {
        "incident_id": incident_id,
        "log_type": "nvidia_api",
        "skill": skill,
        "event": "api_call",
        "model": request_body.get("model"),
        "request_body": request_body,
        "response_status": status_code,
        "response_body": response_json,
        "duration_ms": duration_ms,
        "error": error_msg,
        "tokens_prompt": tokens_prompt,
        "tokens_completion": tokens_completion,
    }

    # Write to file
    _write_to_file({**entry, "timestamp": datetime.now(timezone.utc).isoformat(), "function": function_name})

    # Post to Elixir (fire-and-forget)
    await _post_to_elixir(entry)

    logger.info(
        f"[{skill}/{function_name}] NVIDIA API: {status_code or 'error'} "
        f"in {duration_ms}ms"
        f"{f' (tokens: {tokens_prompt}→{tokens_completion})' if tokens_prompt else ''}"
    )

    return response


async def log_bridge_event(
    event: str,
    skill: str,
    incident_id: str | None = None,
    detail: dict | None = None,
    error: str | None = None,
    duration_ms: int | None = None,
    skill_hash: str | None = None,
):
    """
    Log a NemoClaw bridge application event.

    Events: skill_start, skill_end, rapids_complete, mock_fallback, error
    """
    entry = {
        "incident_id": incident_id,
        "log_type": "bridge_event",
        "skill": skill,
        "skill_hash": skill_hash,
        "event": event,
        "detail": detail,
        "error": error,
        "duration_ms": duration_ms,
    }

    # Write to file
    _write_to_file({**entry, "timestamp": datetime.now(timezone.utc).isoformat()})

    # Post to Elixir
    await _post_to_elixir(entry)

    level = logging.WARNING if event in ("mock_fallback", "error") else logging.INFO
    detail_str = f" — {json.dumps(detail, default=str)}" if detail else ""
    error_str = f" — {error}" if error else ""
    logger.log(level, f"[{skill}] {event}{detail_str}{error_str}")

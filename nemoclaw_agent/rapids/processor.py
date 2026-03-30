"""
RAPIDS telemetry pre-processor.

GPU-accelerated anomaly detection on raw host telemetry using cuDF.
Falls back to pandas on CPU when cuDF is unavailable.

This is production-quality code — the same processor, detectors, and schema
run against real SIEM/EDR telemetry. The only demo-specific behavior is the
auto-inflate logic (controlled by RAPIDS_GENERATE_MOCK env var).
"""

import os
import time
import logging

logger = logging.getLogger("nemoclaw.rapids")

# GPU/CPU fallback — the critical import pattern
try:
    import cudf as pd_impl

    GPU_AVAILABLE = True
    logger.info("RAPIDS cuDF loaded — GPU-accelerated processing enabled")
except ImportError:
    import pandas as pd_impl

    GPU_AVAILABLE = False
    logger.info("cuDF not available — using pandas CPU fallback")

# Demo mode: auto-generate 47k events when input is small
GENERATE_MOCK = os.getenv("RAPIDS_GENERATE_MOCK", "true").lower() in ("true", "1", "yes")

from .schema import Anomaly, AnomalySummary, summary_to_dict
from .detectors import (
    detect_process_anomalies,
    detect_network_anomalies,
    detect_log_frequency_anomalies,
)


def process_telemetry(host_logs: dict, incident: dict | None = None) -> dict:
    """
    Pre-process raw host telemetry and return a ranked anomaly summary.

    In production, host_logs contains thousands of events from CrowdStrike
    Event Streams or SIEM exports. For the demo, small inputs are auto-inflated
    to ~47k events to show the GPU acceleration stat.

    Returns a dict suitable for JSON serialization and inclusion in the
    investigation response.
    """
    start = time.perf_counter()

    host = host_logs.get("host", "UNKNOWN")
    raw_events = host_logs.get("logs", [])

    # Extract incident context for mock telemetry
    _incident = incident or {}
    _username = (
        _incident.get("user_name") or _incident.get("username") or "affected_user"
    )
    _hostname = (
        _incident.get("hostname")
        or (_incident.get("device") or {}).get("hostname")
        or host
        or "WKSTN-042"
    )

    # Demo mode: auto-inflate small inputs with realistic mock data
    if GENERATE_MOCK and len(raw_events) < 100:
        from .mock_telemetry import generate_mock_telemetry

        logger.info(
            f"Small input ({len(raw_events)} events) — generating mock telemetry for demo"
        )
        inflated = generate_mock_telemetry(
            event_count=47_000,
            host=_hostname,
            username=_username,
            existing_events=raw_events if raw_events else None,
        )
        raw_events = inflated["logs"]
        host = inflated["host"]

    total_events = len(raw_events)
    logger.info(f"Processing {total_events:,} events for {host}")

    # Flatten event details into top-level columns for DataFrame construction
    flat_events = _flatten_events(raw_events)

    # Build DataFrame
    df = pd_impl.DataFrame(flat_events) if flat_events else pd_impl.DataFrame()

    # Run detectors
    all_anomalies = []

    # Process anomalies (process creation events)
    proc_df = _filter_process_events(df)
    if not proc_df.empty:
        all_anomalies.extend(detect_process_anomalies(proc_df, pd_impl))

    # Network anomalies (network connection events)
    net_df = _filter_network_events(df)
    if not net_df.empty:
        all_anomalies.extend(detect_network_anomalies(net_df, pd_impl))

    # Log frequency anomalies (all events)
    if not df.empty:
        all_anomalies.extend(detect_log_frequency_anomalies(df, pd_impl))

    # Deduplicate by description
    seen = set()
    unique_anomalies = []
    for a in all_anomalies:
        if a.description not in seen:
            seen.add(a.description)
            unique_anomalies.append(a)

    # Sort by score
    unique_anomalies.sort(key=lambda a: a.score, reverse=True)

    # Build summary stats
    top_talkers = _compute_top_talkers(df)
    event_dist = _compute_event_distribution(df)
    time_range = _compute_time_range(df)

    # Build top indicators (plain-language strings for LLM prompt)
    top_indicators = [a.description for a in unique_anomalies[:8]]

    elapsed_ms = (time.perf_counter() - start) * 1000

    summary = AnomalySummary(
        host=host,
        total_events_processed=total_events,
        processing_time_ms=round(elapsed_ms, 1),
        gpu_accelerated=GPU_AVAILABLE,
        anomaly_count=len(unique_anomalies),
        anomalies=unique_anomalies,
        top_talkers=top_talkers,
        event_distribution=event_dist,
        time_range=time_range,
        top_indicators=top_indicators,
    )

    logger.info(
        f"RAPIDS complete: {total_events:,} events in {elapsed_ms:.0f}ms, "
        f"{len(unique_anomalies)} anomalies ({'GPU' if GPU_AVAILABLE else 'CPU'})"
    )

    return summary_to_dict(summary)


def _flatten_events(events: list[dict]) -> list[dict]:
    """Flatten nested event details into top-level columns."""
    flat = []
    for evt in events:
        row = {
            "timestamp": evt.get("timestamp"),
            "source": evt.get("source"),
            "event_id": evt.get("event_id"),
            "description": evt.get("description"),
        }
        details = evt.get("details", {})
        if isinstance(details, dict):
            row.update(details)
        flat.append(row)
    return flat


def _filter_process_events(df) -> "pd_impl.DataFrame":
    """Filter to process creation events."""
    if df.empty or "event_id" not in df.columns:
        return df.iloc[0:0]

    mask = df["event_id"].isin([4688, 1])
    return df[mask]


def _filter_network_events(df) -> "pd_impl.DataFrame":
    """Filter to network connection events."""
    if df.empty or "event_id" not in df.columns:
        return df.iloc[0:0]

    mask = df["event_id"].isin([3])

    # Also need the network columns to exist
    filtered = df[mask]
    if "destination_ip" not in filtered.columns and "source_ip" not in filtered.columns:
        return df.iloc[0:0]

    return filtered


def _compute_top_talkers(df) -> dict:
    """Compute top processes and destination IPs by frequency."""
    result = {"processes": [], "dest_ips": []}

    if df.empty:
        return result

    if "process" in df.columns:
        proc_counts = df["process"].value_counts().head(10)
        result["processes"] = [
            {"name": str(name), "count": int(count)}
            for name, count in proc_counts.items()
        ]

    if "destination_ip" in df.columns:
        ip_counts = df["destination_ip"].dropna().value_counts().head(10)
        result["dest_ips"] = [
            {"ip": str(ip), "count": int(count)} for ip, count in ip_counts.items()
        ]

    return result


def _compute_event_distribution(df) -> dict:
    """Compute event ID histogram."""
    if df.empty or "event_id" not in df.columns:
        return {}

    counts = df["event_id"].value_counts().head(20)
    return {str(k): int(v) for k, v in counts.items()}


def _compute_time_range(df) -> dict:
    """Compute first and last event timestamps."""
    if df.empty or "timestamp" not in df.columns:
        return {"first": None, "last": None}

    try:
        ts = pd_impl.to_datetime(df["timestamp"], errors="coerce").dropna()
        if ts.empty:
            return {"first": None, "last": None}
        return {"first": str(ts.min()), "last": str(ts.max())}
    except Exception:
        return {"first": None, "last": None}

"""
Typed input/output schemas for the RAPIDS pre-processing pipeline.

These contracts are the same in demo and production — production telemetry
from CrowdStrike Event Streams or Splunk maps to the same RawTelemetry shape,
and the AnomalySummary output feeds the same LLM prompt.
"""

from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class Anomaly:
    """A single detected anomaly, ranked by suspicion score."""

    category: str  # "process", "network", "log_frequency"
    severity: str  # "critical", "high", "medium", "low"
    score: float  # 0.0 - 1.0
    description: str
    evidence: list[str] = field(default_factory=list)
    related_event_ids: list[int] = field(default_factory=list)
    mitre_technique: Optional[str] = None


@dataclass
class AnomalySummary:
    """Output of the RAPIDS pipeline — what the LLM receives."""

    host: str
    total_events_processed: int
    processing_time_ms: float
    gpu_accelerated: bool
    anomaly_count: int
    anomalies: list[Anomaly]
    top_talkers: dict  # {"processes": [...], "dest_ips": [...]}
    event_distribution: dict  # {event_id: count}
    time_range: dict  # {"first": str, "last": str}
    top_indicators: list[str] = field(default_factory=list)  # plain-language for LLM


def summary_to_dict(summary: AnomalySummary) -> dict:
    """Convert AnomalySummary to a JSON-serializable dict."""
    d = asdict(summary)
    # Ensure anomalies are dicts (asdict handles this, but be explicit)
    d["anomalies"] = [asdict(a) if isinstance(a, Anomaly) else a for a in summary.anomalies]
    return d

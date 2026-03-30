"""
Log frequency anomaly detector.

Identifies volume spikes, rare security-sensitive event IDs, and
brute-force login attempt clusters.
"""

import logging

from ..schema import Anomaly

logger = logging.getLogger("nemoclaw.rapids.log_freq")

# Security-sensitive event IDs that are rare in normal operation
SENSITIVE_EVENT_IDS = {
    4698,  # Scheduled Task Created
    4720,  # User Account Created
    4732,  # Member Added to Security-Enabled Local Group
    4756,  # Member Added to Security-Enabled Universal Group
    4728,  # Member Added to Security-Enabled Global Group
    4738,  # User Account Changed
    4735,  # Security-Enabled Local Group Changed
    1102,  # Audit Log Cleared
    4719,  # System Audit Policy Changed
    4697,  # Service Installed
}


def detect_log_frequency_anomalies(df, pd_impl) -> list[Anomaly]:
    """
    Detect frequency anomalies in log events.

    Args:
        df: DataFrame with columns: event_id, timestamp, source, description
        pd_impl: pandas or cudf module
    """
    anomalies = []

    if df.empty or "event_id" not in df.columns:
        return anomalies

    # 1. Rare security-sensitive event IDs
    anomalies.extend(_detect_rare_sensitive_events(df, pd_impl))

    # 2. Volume spikes in time windows
    if "timestamp" in df.columns:
        anomalies.extend(_detect_volume_spikes(df, pd_impl))

    # 3. Failed logon burst detection
    anomalies.extend(_detect_brute_force(df, pd_impl))

    anomalies.sort(key=lambda a: a.score, reverse=True)
    return anomalies


def _detect_rare_sensitive_events(df, pd_impl) -> list[Anomaly]:
    """Flag security-sensitive event IDs that appear rarely."""
    anomalies = []

    try:
        event_counts = df["event_id"].value_counts()
        total = len(df)

        for event_id, count in event_counts.items():
            try:
                eid = int(event_id)
            except (ValueError, TypeError):
                continue

            if eid in SENSITIVE_EVENT_IDS and count <= 5:
                # Get a sample row for context
                sample = df[df["event_id"] == event_id].iloc[0]
                desc = sample.get("description", f"Event {eid}")

                severity = "high" if eid in {1102, 4719, 4720} else "medium"
                score = 0.80 if severity == "high" else 0.65

                anomalies.append(
                    Anomaly(
                        category="log_frequency",
                        severity=severity,
                        score=score,
                        description=f"Rare event ID {eid}: {desc} ({count} of {total:,} events)",
                        evidence=[
                            f"Event ID: {eid}",
                            f"Occurrences: {count}",
                            f"Total events: {total:,}",
                            f"Description: {desc}",
                        ],
                        related_event_ids=[eid],
                        mitre_technique=_event_to_mitre(eid),
                    )
                )
    except Exception as e:
        logger.warning(f"Rare event detection error: {e}")

    return anomalies


def _detect_volume_spikes(df, pd_impl) -> list[Anomaly]:
    """Detect sudden spikes in event volume per time window."""
    anomalies = []

    try:
        df_ts = df.copy()
        df_ts["ts"] = pd_impl.to_datetime(df_ts["timestamp"], errors="coerce")
        df_ts = df_ts.dropna(subset=["ts"])

        if len(df_ts) < 100:
            return anomalies

        # Bin into 5-minute windows
        df_ts["window"] = df_ts["ts"].dt.floor("5min")
        window_counts = df_ts.groupby("window").size()

        if len(window_counts) < 3:
            return anomalies

        mean_vol = window_counts.mean()
        std_vol = window_counts.std()

        if std_vol == 0:
            return anomalies

        # Flag windows > mean + 3*std
        threshold = mean_vol + 3 * std_vol
        spikes = window_counts[window_counts > threshold]

        for window, count in spikes.items():
            ratio = count / mean_vol if mean_vol > 0 else 0
            anomalies.append(
                Anomaly(
                    category="log_frequency",
                    severity="medium",
                    score=min(0.85, 0.5 + ratio * 0.1),
                    description=f"Volume spike: {int(count)} events in 5min window ({ratio:.1f}x baseline)",
                    evidence=[
                        f"Window: {window}",
                        f"Events: {int(count)}",
                        f"Baseline mean: {mean_vol:.0f}/5min",
                        f"Spike ratio: {ratio:.1f}x",
                    ],
                )
            )
    except Exception as e:
        logger.warning(f"Volume spike detection error: {e}")

    return anomalies


def _detect_brute_force(df, pd_impl) -> list[Anomaly]:
    """Detect clusters of failed logon events (event ID 4625)."""
    anomalies = []

    try:
        # Event ID 4625 = Failed Logon
        failed = df[df["event_id"].astype(str) == "4625"]

        if len(failed) < 10:
            return anomalies

        if "timestamp" in failed.columns:
            failed_ts = failed.copy()
            failed_ts["ts"] = pd_impl.to_datetime(failed_ts["timestamp"], errors="coerce")
            failed_ts = failed_ts.dropna(subset=["ts"])

            # Bin into 2-minute windows
            failed_ts["window"] = failed_ts["ts"].dt.floor("2min")
            window_counts = failed_ts.groupby("window").size()

            bursts = window_counts[window_counts > 10]
            for window, count in bursts.items():
                anomalies.append(
                    Anomaly(
                        category="log_frequency",
                        severity="high",
                        score=0.82,
                        description=f"Brute force indicator: {int(count)} failed logons in 2-minute window",
                        evidence=[
                            f"Window: {window}",
                            f"Failed logons: {int(count)}",
                            f"Event ID: 4625",
                        ],
                        related_event_ids=[4625],
                        mitre_technique="T1110",
                    )
                )
    except Exception as e:
        logger.warning(f"Brute force detection error: {e}")

    return anomalies


def _event_to_mitre(event_id: int) -> str | None:
    """Map sensitive event IDs to MITRE techniques."""
    return {
        4698: "T1053.005",  # Scheduled Task
        4720: "T1136.001",  # Create Account
        1102: "T1070.001",  # Clear Windows Event Logs
        4719: "T1562.002",  # Disable Windows Event Logging
        4697: "T1543.003",  # Windows Service
    }.get(event_id)

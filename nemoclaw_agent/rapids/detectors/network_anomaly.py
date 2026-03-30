"""
Network anomaly detector.

Identifies beaconing (regular-interval connections), lateral movement
(SMB/RDP to internal hosts), and exfiltration candidates.
"""

import logging

from ..schema import Anomaly

logger = logging.getLogger("nemoclaw.rapids.network")

# Internal IP prefixes
INTERNAL_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                     "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                     "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                     "172.30.", "172.31.", "192.168.")

# Ports associated with lateral movement
LATERAL_PORTS = {135, 445, 3389, 5985, 5986}


def detect_network_anomalies(df, pd_impl) -> list[Anomaly]:
    """
    Detect network anomalies in connection events.

    Args:
        df: DataFrame with columns: source_ip, destination_ip, destination_port,
            protocol, bytes_sent, pid, timestamp
        pd_impl: pandas or cudf module
    """
    anomalies = []

    if df.empty:
        return anomalies

    has_dst_ip = "destination_ip" in df.columns
    has_dst_port = "destination_port" in df.columns
    has_src_ip = "source_ip" in df.columns
    has_timestamp = "timestamp" in df.columns

    if not (has_dst_ip and has_src_ip):
        return anomalies

    # 1. Beaconing detection — regular interval connections to same external IP
    if has_timestamp and has_dst_ip:
        anomalies.extend(_detect_beaconing(df, pd_impl))

    # 2. Lateral movement — connections on SMB/RDP/WinRM to internal hosts
    if has_dst_ip and has_dst_port:
        anomalies.extend(_detect_lateral_movement(df, pd_impl))

    # 3. Exfiltration candidates — high outbound volume to external IPs
    if has_dst_ip:
        anomalies.extend(_detect_exfiltration(df, pd_impl))

    anomalies.sort(key=lambda a: a.score, reverse=True)
    return anomalies


def _detect_beaconing(df, pd_impl) -> list[Anomaly]:
    """Detect regular-interval outbound connections (C2 beaconing)."""
    anomalies = []

    try:
        df_ts = df.copy()
        df_ts["ts"] = pd_impl.to_datetime(df_ts["timestamp"], errors="coerce")
        df_ts = df_ts.dropna(subset=["ts"])

        # Only external destinations
        external_mask = ~df_ts["destination_ip"].astype(str).str.startswith(INTERNAL_PREFIXES)
        external = df_ts[external_mask]

        if external.empty:
            return anomalies

        # Group by destination IP and analyze connection intervals
        for dst_ip, group in external.groupby("destination_ip"):
            if len(group) < 5:
                continue

            sorted_group = group.sort_values("ts")
            diffs = sorted_group["ts"].diff().dropna()

            if diffs.empty:
                continue

            # Convert to seconds
            diff_seconds = diffs.dt.total_seconds()
            mean_interval = diff_seconds.mean()
            std_interval = diff_seconds.std()

            # Beaconing signal: regular intervals (low std relative to mean)
            if mean_interval > 0 and std_interval < mean_interval * 0.3:
                dst_port = group["destination_port"].iloc[0] if "destination_port" in group.columns else "?"
                anomalies.append(
                    Anomaly(
                        category="network",
                        severity="critical",
                        score=0.95,
                        description=f"Beaconing detected: ~{mean_interval:.0f}s interval to {dst_ip}:{dst_port}",
                        evidence=[
                            f"Destination: {dst_ip}:{dst_port}",
                            f"Connections: {len(group)}",
                            f"Mean interval: {mean_interval:.1f}s",
                            f"Interval std: {std_interval:.1f}s (low = regular)",
                            f"Source: {group['source_ip'].iloc[0]}",
                        ],
                        mitre_technique="T1071.001",
                    )
                )
    except Exception as e:
        logger.warning(f"Beaconing detection error: {e}")

    return anomalies


def _detect_lateral_movement(df, pd_impl) -> list[Anomaly]:
    """Detect connections on lateral movement ports to internal hosts."""
    anomalies = []

    try:
        # Filter to lateral movement ports
        port_col = df["destination_port"].astype(int)
        lateral_mask = port_col.isin(list(LATERAL_PORTS))
        lateral = df[lateral_mask]

        if lateral.empty:
            return anomalies

        # Filter to internal destinations
        dst_str = lateral["destination_ip"].astype(str)
        internal_mask = dst_str.str.startswith(INTERNAL_PREFIXES)
        internal_lateral = lateral[internal_mask]

        if internal_lateral.empty:
            return anomalies

        # Group by source IP — flag sources hitting multiple internal targets
        for src_ip, group in internal_lateral.groupby("source_ip"):
            unique_targets = group["destination_ip"].nunique()
            if unique_targets >= 2:
                targets = group["destination_ip"].unique().tolist()
                ports = group["destination_port"].unique().tolist()
                anomalies.append(
                    Anomaly(
                        category="network",
                        severity="high",
                        score=0.88,
                        description=f"Lateral movement: {src_ip} connecting to {unique_targets} internal hosts on port(s) {ports}",
                        evidence=[
                            f"Source: {src_ip}",
                            f"Targets: {', '.join(str(t) for t in targets[:5])}",
                            f"Ports: {', '.join(str(p) for p in ports)}",
                            f"Connections: {len(group)}",
                        ],
                        mitre_technique="T1021.002",
                    )
                )
    except Exception as e:
        logger.warning(f"Lateral movement detection error: {e}")

    return anomalies


def _detect_exfiltration(df, pd_impl) -> list[Anomaly]:
    """Detect high-volume outbound connections to external IPs."""
    anomalies = []

    try:
        # External destinations only
        external_mask = ~df["destination_ip"].astype(str).str.startswith(INTERNAL_PREFIXES)
        external = df[external_mask]

        if external.empty or "bytes_sent" not in external.columns:
            return anomalies

        # Group by destination IP, sum bytes
        by_dest = external.groupby("destination_ip")["bytes_sent"].sum()
        high_volume = by_dest[by_dest > 100_000].sort_values(ascending=False)

        for dst_ip, total_bytes in high_volume.head(3).items():
            anomalies.append(
                Anomaly(
                    category="network",
                    severity="high",
                    score=0.75,
                    description=f"High outbound volume to {dst_ip}: {total_bytes:,.0f} bytes",
                    evidence=[
                        f"Destination: {dst_ip}",
                        f"Total bytes: {total_bytes:,.0f}",
                        f"Connections: {len(external[external['destination_ip'] == dst_ip])}",
                    ],
                    mitre_technique="T1041",
                )
            )
    except Exception as e:
        logger.warning(f"Exfiltration detection error: {e}")

    return anomalies

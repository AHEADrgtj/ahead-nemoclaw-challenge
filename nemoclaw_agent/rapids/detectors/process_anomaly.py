"""
Process anomaly detector.

Identifies suspicious parent-child process relationships, execution from
temp/unusual directories, encoded command-line arguments, and rare process names.

Uses the same detection logic in demo and production — only the input data source changes.
"""

import logging

from ..schema import Anomaly

logger = logging.getLogger("nemoclaw.rapids.process")

# Known-suspicious parent → child spawn patterns (LOLBins)
SUSPICIOUS_PAIRS = {
    ("winword.exe", "powershell.exe"),
    ("winword.exe", "cmd.exe"),
    ("winword.exe", "wscript.exe"),
    ("winword.exe", "cscript.exe"),
    ("excel.exe", "powershell.exe"),
    ("excel.exe", "cmd.exe"),
    ("wmiprvse.exe", "cmd.exe"),
    ("wmiprvse.exe", "powershell.exe"),
    ("svchost.exe", "cmd.exe"),
    ("explorer.exe", "wmic.exe"),
    ("outlook.exe", "powershell.exe"),
    ("mshta.exe", "powershell.exe"),
}

# Paths that are unusual for legitimate process execution
SUSPICIOUS_PATH_PATTERNS = [
    r"\\Temp\\",
    r"\\AppData\\",
    r"\\Users\\Public\\",
    r"\\ProgramData\\",
    r"\\Windows\\Temp\\",
    r"\\Downloads\\",
]

# Encoded command indicators
ENCODED_INDICATORS = [
    "-EncodedCommand",
    "-enc ",
    "FromBase64String",
    "[Convert]::",
    "-WindowStyle Hidden",
    "-W Hidden",
    "-NoP ",
    "-NonI ",
]


def detect_process_anomalies(df, pd_impl) -> list[Anomaly]:
    """
    Detect process anomalies in process creation events.

    Args:
        df: DataFrame with columns: process, parent, command_line, pid, user, timestamp
        pd_impl: pandas or cudf module
    """
    anomalies = []

    if df.empty:
        return anomalies

    # Normalize to lowercase for comparison
    has_parent = "parent" in df.columns
    has_cmdline = "command_line" in df.columns
    has_process = "process" in df.columns

    if not has_process:
        return anomalies

    proc_lower = df["process"].astype(str).str.lower()

    # 1. Suspicious parent-child pairs
    if has_parent:
        parent_lower = df["parent"].astype(str).str.lower()

        for parent_pat, child_pat in SUSPICIOUS_PAIRS:
            mask = (parent_lower.str.contains(parent_pat, na=False)) & (
                proc_lower.str.contains(child_pat, na=False)
            )
            matches = df[mask]
            for _, row in matches.iterrows():
                anomalies.append(
                    Anomaly(
                        category="process",
                        severity="critical",
                        score=0.95,
                        description=f"Suspicious parent-child: {row.get('parent', '?')} spawned {row['process']}",
                        evidence=[
                            f"Parent: {row.get('parent', '?')} (PID {row.get('parent_pid', '?')})",
                            f"Child: {row['process']} (PID {row.get('pid', '?')})",
                            f"User: {row.get('user', '?')}",
                            f"Command: {str(row.get('command_line', ''))[:120]}",
                        ],
                        related_event_ids=[int(row["pid"])] if "pid" in row and row["pid"] else [],
                        mitre_technique="T1059.001",
                    )
                )

    # 2. Execution from suspicious paths
    if has_cmdline:
        cmdline = df["command_line"].astype(str)
        for pattern in SUSPICIOUS_PATH_PATTERNS:
            mask = cmdline.str.contains(pattern, regex=True, na=False)
            matches = df[mask]
            for _, row in matches.iterrows():
                # Skip if already flagged by parent-child detection
                if any(
                    a.description.startswith("Suspicious parent-child")
                    and str(row.get("pid", "")) in str(a.related_event_ids)
                    for a in anomalies
                ):
                    continue
                anomalies.append(
                    Anomaly(
                        category="process",
                        severity="high",
                        score=0.80,
                        description=f"Execution from suspicious path: {row['process']}",
                        evidence=[
                            f"Process: {row['process']}",
                            f"Command: {str(row.get('command_line', ''))[:120]}",
                            f"Matched pattern: {pattern}",
                        ],
                        mitre_technique="T1036.005",
                    )
                )

    # 3. Encoded command arguments
    if has_cmdline:
        cmdline = df["command_line"].astype(str)
        for indicator in ENCODED_INDICATORS:
            mask = cmdline.str.contains(indicator, case=False, na=False, regex=False)
            matches = df[mask]
            for _, row in matches.iterrows():
                # Deduplicate — only flag once per PID
                pid = row.get("pid")
                if pid and any(pid in a.related_event_ids for a in anomalies):
                    continue
                anomalies.append(
                    Anomaly(
                        category="process",
                        severity="high",
                        score=0.85,
                        description=f"Encoded/obfuscated command detected: {row['process']}",
                        evidence=[
                            f"Process: {row['process']}",
                            f"Indicator: {indicator}",
                            f"Command: {str(row.get('command_line', ''))[:120]}",
                        ],
                        related_event_ids=[int(pid)] if pid else [],
                        mitre_technique="T1059.001",
                    )
                )
                break  # One anomaly per indicator match is enough

    # 4. Rare process names (frequency-based)
    value_counts = proc_lower.value_counts()
    total = len(proc_lower)
    rare_threshold = max(3, total * 0.0001)  # <0.01% of events or <3 occurrences
    rare_procs = value_counts[value_counts <= rare_threshold]

    for proc_name, count in rare_procs.items():
        if proc_name in ("nan", "", "none"):
            continue
        # Skip known-rare-but-legitimate
        if proc_name in ("taskmgr.exe", "mmc.exe", "regedit.exe", "notepad.exe"):
            continue
        matches = df[proc_lower == proc_name]
        if not matches.empty:
            row = matches.iloc[0]
            anomalies.append(
                Anomaly(
                    category="process",
                    severity="medium",
                    score=0.60,
                    description=f"Rare process: {row['process']} ({count} of {total} events)",
                    evidence=[
                        f"Process: {row['process']}",
                        f"Frequency: {count}/{total} events",
                        f"User: {row.get('user', '?')}",
                    ],
                    mitre_technique=None,
                )
            )

    # Sort by score descending
    anomalies.sort(key=lambda a: a.score, reverse=True)
    return anomalies

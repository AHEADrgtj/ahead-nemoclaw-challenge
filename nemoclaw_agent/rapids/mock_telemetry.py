"""
Mock telemetry generator.

Produces ~47,000 realistic Windows Security/Sysmon events with planted
anomalies that reliably trigger each detector. Demo-only — in production,
telemetry comes from CrowdStrike Event Streams or SIEM exports.

The generator is deterministic (seeded) so demo results are reproducible.
"""

import random
from datetime import datetime, timedelta, timezone

# Normal processes seen on a typical Windows workstation
NORMAL_PROCESSES = [
    ("svchost.exe", "services.exe", "SYSTEM"),
    ("chrome.exe", "explorer.exe", "{user}"),
    ("outlook.exe", "explorer.exe", "{user}"),
    ("explorer.exe", "userinit.exe", "{user}"),
    ("taskhostw.exe", "svchost.exe", "SYSTEM"),
    ("RuntimeBroker.exe", "svchost.exe", "{user}"),
    ("SearchIndexer.exe", "services.exe", "SYSTEM"),
    ("MsMpEng.exe", "services.exe", "SYSTEM"),
    ("dwm.exe", "winlogon.exe", "DWM-1"),
    ("conhost.exe", "csrss.exe", "SYSTEM"),
    ("lsass.exe", "wininit.exe", "SYSTEM"),
    ("spoolsv.exe", "services.exe", "SYSTEM"),
    ("mstsc.exe", "explorer.exe", "{user}"),
    ("notepad.exe", "explorer.exe", "{user}"),
    ("Teams.exe", "explorer.exe", "{user}"),
]

# Normal internal IPs
INTERNAL_IPS = [f"10.128.4.{i}" for i in range(1, 60)]

# Normal external IPs (CDNs, Microsoft, Google, etc.)
NORMAL_EXTERNAL_IPS = [
    "13.107.42.14",   # Microsoft
    "142.250.80.46",  # Google
    "151.101.1.69",   # Fastly/CDN
    "104.18.32.7",    # Cloudflare
    "20.190.159.2",   # Azure AD
    "52.96.166.130",  # Office 365
]

# Normal destination ports
NORMAL_PORTS = [80, 443, 53, 8080, 8443]

# Event ID weights for realistic distribution
EVENT_WEIGHTS = {
    4688: 40,   # Process Create
    4624: 15,   # Successful Logon
    3: 20,      # Sysmon Network Connection
    4672: 10,   # Special Logon
    4634: 5,    # Logoff
    11: 3,      # Sysmon File Create
    1: 3,       # Sysmon Process Create
    7: 2,       # Sysmon Image Loaded
    22: 2,      # Sysmon DNS Query
}


def generate_mock_telemetry(
    event_count: int = 47_000,
    host: str = "WKSTN-042",
    username: str = "affected_user",
    seed: int = 42,
    existing_events: list | None = None,
) -> dict:
    """
    Generate realistic host telemetry with planted anomalies.

    Args:
        event_count: Total events to generate (~47k for demo stat)
        host: Hostname
        username: Affected user (from the incident)
        seed: Random seed for reproducibility
        existing_events: If provided, seed these into the generated data
    """
    rng = random.Random(seed)
    now = datetime.now(timezone.utc)
    events = []

    # Reserve slots for planted anomalies
    anomaly_count = 200
    baseline_count = event_count - anomaly_count

    # 1. Generate baseline noise
    event_ids = _weighted_choices(EVENT_WEIGHTS, baseline_count, rng)

    for i, event_id in enumerate(event_ids):
        # Spread over 24 hours with realistic burst patterns
        hours_ago = rng.random() * 24
        # Heavier between 9am-5pm
        if rng.random() < 0.6:
            hours_ago = rng.uniform(1, 9)  # Recent business hours

        ts = now - timedelta(hours=hours_ago, seconds=rng.random() * 60)

        event = _generate_baseline_event(event_id, ts, host, username, rng)
        events.append(event)

    # 2. Plant anomalies that reliably trigger each detector
    events.extend(_plant_process_anomalies(now, host, username, rng))
    events.extend(_plant_network_beaconing(now, host, username, rng))
    events.extend(_plant_lateral_movement(now, host, username, rng))
    events.extend(_plant_rare_events(now, host, username, rng))
    events.extend(_plant_failed_logons(now, host, username, rng))

    # 3. Seed existing events if provided
    if existing_events:
        events.extend(existing_events)

    # Shuffle so anomalies aren't clustered at the end
    rng.shuffle(events)

    return {
        "host": host,
        "collection_time": now.isoformat(),
        "logs": events,
    }


def _weighted_choices(weights: dict, count: int, rng: random.Random) -> list:
    """Pick count items from weighted dict."""
    ids = list(weights.keys())
    wts = list(weights.values())
    return rng.choices(ids, weights=wts, k=count)


def _generate_baseline_event(event_id: int, ts: datetime, host: str, username: str, rng: random.Random) -> dict:
    """Generate a single normal event."""
    if event_id in (4688, 1):  # Process creation
        proc, parent, user_template = rng.choice(NORMAL_PROCESSES)
        user = user_template.replace("{user}", username)
        return {
            "timestamp": ts.isoformat(),
            "source": "Security" if event_id == 4688 else "Sysmon",
            "event_id": event_id,
            "description": "A new process has been created",
            "details": {
                "process": proc,
                "pid": rng.randint(100, 65000),
                "parent": parent,
                "parent_pid": rng.randint(100, 65000),
                "user": f"ACMECORP\\{user}",
                "command_line": f"{proc}",
            },
        }
    elif event_id == 3:  # Network connection
        src_ip = f"10.128.4.{rng.randint(1, 59)}"
        if rng.random() < 0.7:
            dst_ip = rng.choice(NORMAL_EXTERNAL_IPS)
            dst_port = rng.choice([80, 443])
        else:
            dst_ip = rng.choice(INTERNAL_IPS)
            dst_port = rng.choice(NORMAL_PORTS)
        proc, _, _ = rng.choice(NORMAL_PROCESSES[:6])
        return {
            "timestamp": ts.isoformat(),
            "source": "Sysmon",
            "event_id": 3,
            "description": "Network connection detected",
            "details": {
                "process": proc,
                "pid": rng.randint(100, 65000),
                "source_ip": src_ip,
                "source_port": rng.randint(49152, 65535),
                "destination_ip": dst_ip,
                "destination_port": dst_port,
                "protocol": "tcp",
                "bytes_sent": rng.randint(100, 5000),
            },
        }
    elif event_id == 4624:  # Successful logon
        return {
            "timestamp": ts.isoformat(),
            "source": "Security",
            "event_id": 4624,
            "description": "An account was successfully logged on",
            "details": {
                "logon_type": rng.choice([2, 3, 10]),
                "user": f"ACMECORP\\{rng.choice([username, 'admin', 'svc_backup'])}",
                "source_ip": rng.choice(INTERNAL_IPS),
            },
        }
    else:
        return {
            "timestamp": ts.isoformat(),
            "source": rng.choice(["Security", "Sysmon"]),
            "event_id": event_id,
            "description": f"Event {event_id}",
            "details": {"process": rng.choice(NORMAL_PROCESSES)[0]},
        }


def _plant_process_anomalies(now: datetime, host: str, username: str, rng: random.Random) -> list:
    """Plant suspicious parent-child process spawns."""
    events = []
    base = now - timedelta(minutes=10)

    # WINWORD.EXE spawns powershell.exe with encoded command
    events.append({
        "timestamp": (base + timedelta(seconds=22)).isoformat(),
        "source": "Security",
        "event_id": 4688,
        "description": "A new process has been created",
        "details": {
            "process": "powershell.exe",
            "pid": 7284,
            "parent": "WINWORD.EXE",
            "parent_pid": 4812,
            "user": f"ACMECORP\\{username}",
            "command_line": "powershell.exe -NoP -NonI -W Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA...",
        },
    })

    # WINWORD.EXE process (the parent)
    events.append({
        "timestamp": base.isoformat(),
        "source": "Security",
        "event_id": 4688,
        "description": "A new process has been created",
        "details": {
            "process": "WINWORD.EXE",
            "pid": 4812,
            "parent": "explorer.exe",
            "parent_pid": 2100,
            "user": f"ACMECORP\\{username}",
            "command_line": f'"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" /n "C:\\Users\\{username}\\Downloads\\Q4-Financial-Review-2026.docm"',
        },
    })

    # Dropped binary in ProgramData
    events.append({
        "timestamp": (base + timedelta(seconds=62)).isoformat(),
        "source": "Sysmon",
        "event_id": 11,
        "description": "File created",
        "details": {
            "process": "powershell.exe",
            "pid": 7284,
            "target_filename": "C:\\ProgramData\\svchost.exe",
            "command_line": "C:\\ProgramData\\svchost.exe",
        },
    })

    # Fake svchost from ProgramData (masquerading)
    events.append({
        "timestamp": (base + timedelta(seconds=120)).isoformat(),
        "source": "Security",
        "event_id": 4688,
        "description": "A new process has been created",
        "details": {
            "process": "svchost.exe",
            "pid": 9102,
            "parent": "powershell.exe",
            "parent_pid": 7284,
            "user": f"ACMECORP\\{username}",
            "command_line": "C:\\ProgramData\\svchost.exe -k netsvcs",
        },
    })

    # wmic lateral movement attempt
    events.append({
        "timestamp": (base + timedelta(seconds=150)).isoformat(),
        "source": "Sysmon",
        "event_id": 1,
        "description": "Process Create",
        "details": {
            "process": "wmic.exe",
            "pid": 8412,
            "parent": "powershell.exe",
            "parent_pid": 7284,
            "user": f"ACMECORP\\{username}",
            "command_line": 'wmic /node:WKSTN-043 process call create "cmd /c echo test > C:\\Users\\Public\\test.txt"',
        },
    })

    return events


def _plant_network_beaconing(now: datetime, host: str, username: str, rng: random.Random) -> list:
    """Plant regular-interval C2 beaconing."""
    events = []

    # 12 connections at ~60-second intervals to C2 IP
    for i in range(12):
        jitter = rng.uniform(-3, 3)  # Small jitter to be realistic but still detectable
        ts = now - timedelta(minutes=i, seconds=jitter)
        events.append({
            "timestamp": ts.isoformat(),
            "source": "Sysmon",
            "event_id": 3,
            "description": "Network connection detected",
            "details": {
                "process": "powershell.exe",
                "pid": 7284,
                "source_ip": "10.128.4.42",
                "source_port": 49832 + i,
                "destination_ip": "185.220.101.42",
                "destination_port": 443,
                "protocol": "tcp",
                "bytes_sent": rng.randint(800, 1200),
            },
        })

    # Persisted beacon from dropped svchost
    for i in range(8):
        jitter = rng.uniform(-3, 3)
        ts = now - timedelta(minutes=15 + i, seconds=jitter)
        events.append({
            "timestamp": ts.isoformat(),
            "source": "Sysmon",
            "event_id": 3,
            "description": "Network connection detected",
            "details": {
                "process": "svchost.exe",
                "pid": 9102,
                "source_ip": "10.128.4.42",
                "source_port": 49900 + i,
                "destination_ip": "185.220.101.42",
                "destination_port": 443,
                "protocol": "tcp",
                "bytes_sent": rng.randint(1000, 2000),
            },
        })

    return events


def _plant_lateral_movement(now: datetime, host: str, username: str, rng: random.Random) -> list:
    """Plant SMB/WMI lateral movement to internal hosts."""
    events = []
    base = now - timedelta(minutes=8)

    targets = ["10.128.4.43", "10.128.4.44", "10.128.4.55"]
    for i, target in enumerate(targets):
        # SMB connection (port 445)
        events.append({
            "timestamp": (base + timedelta(seconds=i * 10)).isoformat(),
            "source": "Sysmon",
            "event_id": 3,
            "description": "Network connection detected",
            "details": {
                "process": "wmic.exe",
                "pid": 8412,
                "source_ip": "10.128.4.42",
                "source_port": 49847 + i,
                "destination_ip": target,
                "destination_port": 445,
                "protocol": "tcp",
                "bytes_sent": 4096,
            },
        })

        # WMI connection (port 135)
        events.append({
            "timestamp": (base + timedelta(seconds=i * 10 + 1)).isoformat(),
            "source": "Sysmon",
            "event_id": 3,
            "description": "Network connection detected",
            "details": {
                "process": "wmic.exe",
                "pid": 8412,
                "source_ip": "10.128.4.42",
                "source_port": 49860 + i,
                "destination_ip": target,
                "destination_port": 135,
                "protocol": "tcp",
                "bytes_sent": 2048,
            },
        })

    return events


def _plant_rare_events(now: datetime, host: str, username: str, rng: random.Random) -> list:
    """Plant rare security-sensitive events."""
    base = now - timedelta(minutes=7)

    return [
        {
            "timestamp": (base + timedelta(seconds=5)).isoformat(),
            "source": "Security",
            "event_id": 4698,
            "description": "A scheduled task was created",
            "details": {
                "task_name": "\\Microsoft\\Windows\\Maintenance\\WinSvc",
                "process": "schtasks.exe",
                "pid": 8500,
                "user": f"ACMECORP\\{username}",
                "command_line": "schtasks /create /tn WinSvc /tr C:\\ProgramData\\svchost.exe",
            },
        },
    ]


def _plant_failed_logons(now: datetime, host: str, username: str, rng: random.Random) -> list:
    """Plant burst of failed logon events (brute force indicator)."""
    events = []
    base = now - timedelta(minutes=20)

    # 15 failed logons in a 2-minute window
    for i in range(15):
        ts = base + timedelta(seconds=rng.uniform(0, 120))
        events.append({
            "timestamp": ts.isoformat(),
            "source": "Security",
            "event_id": 4625,
            "description": "An account failed to log on",
            "details": {
                "logon_type": 3,
                "user": f"ACMECORP\\{rng.choice(['admin', 'administrator', 'svc_sql'])}",
                "source_ip": "10.128.4.42",
                "failure_reason": "Unknown user name or bad password",
                "process": "NtLmSsp",
                "pid": 0,
            },
        })

    return events

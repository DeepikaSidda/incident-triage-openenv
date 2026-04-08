"""Medium scenario: Lateral movement across internal network.

An attacker compromised web-server-01 via a phishing email containing a
malicious attachment.  Using stolen service-account credentials (svc-deploy),
the attacker moved laterally to app-server-01 and file-server-01.  The agent
must investigate alerts across multiple hosts, correlate the attack chain,
isolate compromised systems, and file a comprehensive report.
"""

from models import Alert, GroundTruth, LogEntry, TaskDefinition

TASK = TaskDefinition(
    name="lateral_movement",
    difficulty="medium",
    max_steps=25,
    description=(
        "An attacker compromised web-server-01 via a phishing email and is "
        "moving laterally to app-server-01 and file-server-01 using stolen "
        "service-account credentials. Investigate alerts from multiple hosts, "
        "correlate the attack chain, isolate all compromised systems, revoke "
        "compromised credentials, and submit a final incident report."
    ),
    # ------------------------------------------------------------------
    # Initial alerts (4 malicious + 2 benign decoys)
    # ------------------------------------------------------------------
    initial_alerts=[
        Alert(
            id="alert-lm-001",
            timestamp="2025-01-15T14:05:22Z",
            source="edr-monitor",
            severity="High",
            message=(
                "Suspicious process execution on web-server-01: "
                "powershell.exe spawned from outlook.exe with encoded "
                "command-line arguments (PID 7841)"
            ),
        ),
        Alert(
            id="alert-lm-002",
            timestamp="2025-01-15T14:18:37Z",
            source="auth-logs",
            severity="High",
            message=(
                "Unusual authentication: svc-deploy logged into "
                "app-server-01 from web-server-01 via SMB — first time "
                "this source-destination pair has been observed"
            ),
        ),
        Alert(
            id="alert-lm-003",
            timestamp="2025-01-15T14:32:09Z",
            source="network-flows",
            severity="High",
            message=(
                "Suspicious RDP connection from app-server-01 to "
                "file-server-01 on port 3389 — svc-deploy account used, "
                "outside normal service window"
            ),
        ),
        Alert(
            id="alert-lm-004",
            timestamp="2025-01-15T14:45:51Z",
            source="edr-monitor",
            severity="Medium",
            message=(
                "Credential dumping tool detected on web-server-01: "
                "mimikatz.exe executed under svc-deploy context "
                "(PID 8102, parent PID 7841)"
            ),
        ),
        Alert(
            id="alert-lm-005",
            timestamp="2025-01-15T14:52:14Z",
            source="network-flows",
            severity="Medium",
            message=(
                "Anomalous SMB file copy activity from app-server-01 to "
                "file-server-01 — 847 MB transferred in 4 minutes over "
                "port 445"
            ),
        ),
        Alert(
            id="alert-lm-006",
            timestamp="2025-01-15T14:10:00Z",
            source="app-monitor",
            severity="Low",
            message=(
                "Scheduled backup job on db-server-01 completed "
                "successfully — 12.3 GB written to /mnt/backup"
            ),
        ),
    ],
    # ------------------------------------------------------------------
    # Initial logs (8 entries across hosts)
    # ------------------------------------------------------------------
    initial_logs=[
        LogEntry(
            timestamp="2025-01-15T14:03:48Z",
            source="process-logs",
            level="INFO",
            content=(
                "web-server-01 outlook.exe (PID 6210) opened attachment "
                "Q4-Report-Final.docm from sender external-partner@198.51.100.23"
            ),
        ),
        LogEntry(
            timestamp="2025-01-15T14:05:20Z",
            source="process-logs",
            level="WARNING",
            content=(
                "web-server-01 powershell.exe (PID 7841) spawned by "
                "outlook.exe (PID 6210) — encoded command detected: "
                "-enc SQBFAFgAIAAoA..."
            ),
        ),
        LogEntry(
            timestamp="2025-01-15T14:08:33Z",
            source="network-flows",
            level="INFO",
            content=(
                "Outbound connection from web-server-01:49152 to "
                "198.51.100.23:443 — TLS handshake completed, "
                "C2 beacon pattern suspected"
            ),
        ),
        LogEntry(
            timestamp="2025-01-15T14:15:02Z",
            source="auth-logs",
            level="WARNING",
            content=(
                "web-server-01 svc-deploy credential used for interactive "
                "logon — normally a service-only account (logon type 10)"
            ),
        ),
        LogEntry(
            timestamp="2025-01-15T14:18:35Z",
            source="auth-logs",
            level="WARNING",
            content=(
                "app-server-01 svc-deploy authenticated via NTLM from "
                "web-server-01 (10.0.1.10) — new source for this account"
            ),
        ),
        LogEntry(
            timestamp="2025-01-15T14:30:44Z",
            source="network-flows",
            level="INFO",
            content=(
                "RDP session initiated: app-server-01 (10.0.2.20) -> "
                "file-server-01 (10.0.3.30) port 3389 — user svc-deploy"
            ),
        ),
        LogEntry(
            timestamp="2025-01-15T14:44:18Z",
            source="process-logs",
            level="CRITICAL",
            content=(
                "web-server-01 mimikatz.exe (PID 8102) executed — "
                "LSASS memory access detected, credential extraction "
                "in progress"
            ),
        ),
        LogEntry(
            timestamp="2025-01-15T14:50:55Z",
            source="network-flows",
            level="WARNING",
            content=(
                "High-volume SMB transfer: app-server-01 -> "
                "file-server-01 port 445 — 847 MB in 240 seconds, "
                "destination share \\\\file-server-01\\staging"
            ),
        ),
    ],
    # ------------------------------------------------------------------
    # System status
    # ------------------------------------------------------------------
    system_status={
        "web-server-01": "compromised",
        "app-server-01": "suspicious",
        "file-server-01": "suspicious",
        "db-server-01": "operational",
        "admin-workstation-01": "operational",
    },
    # ------------------------------------------------------------------
    # Network topology
    # ------------------------------------------------------------------
    network_topology={
        "web-server-01": ["app-server-01", "db-server-01"],
        "app-server-01": ["web-server-01", "db-server-01", "file-server-01"],
        "db-server-01": ["app-server-01"],
        "file-server-01": ["app-server-01", "admin-workstation-01"],
        "admin-workstation-01": ["file-server-01"],
    },
    # ------------------------------------------------------------------
    # Valid investigation / remediation targets
    # ------------------------------------------------------------------
    valid_components={
        "web-server-01",
        "app-server-01",
        "file-server-01",
        "db-server-01",
        "admin-workstation-01",
        "edr-monitor",
        "network-flows",
        "auth-logs",
        "process-logs",
        "firewall",
    },
    # ------------------------------------------------------------------
    # Ground truth
    # ------------------------------------------------------------------
    ground_truth=GroundTruth(
        severity="Critical",
        malicious_ips=["198.51.100.23"],
        compromised_hosts=["web-server-01", "app-server-01", "file-server-01"],
        compromised_accounts=["svc-deploy"],
        attack_method="lateral_movement_via_stolen_credentials",
        exfil_destination=None,
        correlated_alert_groups=[
            ["alert-lm-001", "alert-lm-002", "alert-lm-003"],
            ["alert-lm-004", "alert-lm-005"],
        ],
        correct_remediations=[
            {
                "action_type": "remediate",
                "target": "web-server-01",
                "params": {"action": "isolate_host"},
            },
            {
                "action_type": "remediate",
                "target": "app-server-01",
                "params": {"action": "isolate_host"},
            },
            {
                "action_type": "remediate",
                "target": "file-server-01",
                "params": {"action": "isolate_host"},
            },
            {
                "action_type": "remediate",
                "target": "auth-logs",
                "params": {
                    "action": "revoke_credentials",
                    "account": "svc-deploy",
                },
            },
        ],
        incorrect_remediations=[
            {
                "action_type": "remediate",
                "target": "db-server-01",
                "params": {"action": "shutdown"},
            },
            {
                "action_type": "remediate",
                "target": "admin-workstation-01",
                "params": {"action": "shutdown"},
            },
        ],
        report_required_fields={
            "compromised_hosts": "web-server-01, app-server-01, file-server-01",
            "attack_path": (
                "web-server-01 -> app-server-01 -> file-server-01"
            ),
            "severity": "Critical",
            "remediations": (
                "isolate_host, revoke_credentials"
            ),
        },
    ),
    # ------------------------------------------------------------------
    # Investigable sources — hidden logs revealed on investigate
    # ------------------------------------------------------------------
    investigable_sources={
        "edr-monitor": [
            LogEntry(
                timestamp="2025-01-15T14:05:25Z",
                source="edr-monitor",
                level="WARNING",
                content=(
                    "web-server-01 powershell.exe (PID 7841) loaded "
                    "suspicious DLL: amsi_bypass.dll — AMSI evasion "
                    "technique detected"
                ),
            ),
            LogEntry(
                timestamp="2025-01-15T14:44:22Z",
                source="edr-monitor",
                level="CRITICAL",
                content=(
                    "web-server-01 mimikatz.exe (PID 8102) accessed "
                    "LSASS process memory — extracted 3 credential sets "
                    "including svc-deploy NTLM hash"
                ),
            ),
            LogEntry(
                timestamp="2025-01-15T14:55:10Z",
                source="edr-monitor",
                level="WARNING",
                content=(
                    "file-server-01 cmd.exe (PID 3301) spawned by "
                    "svc-deploy — executing net share and dir commands "
                    "for reconnaissance"
                ),
            ),
        ],
        "network-flows": [
            LogEntry(
                timestamp="2025-01-15T14:08:35Z",
                source="network-flows",
                level="WARNING",
                content=(
                    "web-server-01 (10.0.1.10) -> 198.51.100.23:443 "
                    "periodic beacon: 30-second interval, 256-byte "
                    "payload — matches known C2 pattern"
                ),
            ),
            LogEntry(
                timestamp="2025-01-15T14:19:02Z",
                source="network-flows",
                level="INFO",
                content=(
                    "SMB session: web-server-01 (10.0.1.10) -> "
                    "app-server-01 (10.0.2.20) port 445 — "
                    "authenticated as svc-deploy, 12 files accessed"
                ),
            ),
            LogEntry(
                timestamp="2025-01-15T14:33:15Z",
                source="network-flows",
                level="WARNING",
                content=(
                    "RDP tunnel: app-server-01 (10.0.2.20) -> "
                    "file-server-01 (10.0.3.30) port 3389 — session "
                    "duration 22 minutes, 847 MB transferred"
                ),
            ),
        ],
        "process-logs": [
            LogEntry(
                timestamp="2025-01-15T14:06:11Z",
                source="process-logs",
                level="WARNING",
                content=(
                    "web-server-01 powershell.exe (PID 7841) downloaded "
                    "payload from 198.51.100.23/stage2.bin to "
                    "C:\\Users\\svc-deploy\\AppData\\Local\\Temp\\svchost.exe"
                ),
            ),
            LogEntry(
                timestamp="2025-01-15T14:20:45Z",
                source="process-logs",
                level="INFO",
                content=(
                    "app-server-01 svc-deploy executed whoami /priv and "
                    "net group 'Domain Admins' — enumeration activity"
                ),
            ),
        ],
        "auth-logs": [
            LogEntry(
                timestamp="2025-01-15T14:14:58Z",
                source="auth-logs",
                level="WARNING",
                content=(
                    "web-server-01 svc-deploy interactive logon (type 10) "
                    "from console — account normally uses service logon "
                    "(type 5) only"
                ),
            ),
            LogEntry(
                timestamp="2025-01-15T14:31:02Z",
                source="auth-logs",
                level="WARNING",
                content=(
                    "file-server-01 svc-deploy authenticated via NTLM "
                    "from app-server-01 (10.0.2.20) — pass-the-hash "
                    "attack suspected, logon type 3"
                ),
            ),
            LogEntry(
                timestamp="2025-01-15T14:56:30Z",
                source="auth-logs",
                level="CRITICAL",
                content=(
                    "file-server-01 svc-deploy elevated to local admin "
                    "via token impersonation — privilege escalation "
                    "confirmed"
                ),
            ),
        ],
    },
    # ------------------------------------------------------------------
    # Rubric weights
    # ------------------------------------------------------------------
    rubric_weights={
        "investigation": 0.25,
        "classification": 0.15,
        "correlation": 0.20,
        "remediation": 0.20,
        "report": 0.20,
    },
)

"""Easy scenario: Brute-force SSH login attempt against a single server.

An attacker at 198.51.100.23 repeatedly tries SSH credentials against
web-server-01.  After many failures the attacker succeeds with the
'admin' account.  The agent must investigate, classify, remediate
(block the IP), and file a report.
"""

from models import Alert, GroundTruth, LogEntry, TaskDefinition

TASK = TaskDefinition(
    name="brute_force_login",
    difficulty="easy",
    max_steps=15,
    description=(
        "A brute-force SSH login attack has been detected targeting web-server-01. "
        "Multiple failed authentication attempts originate from a single external IP. "
        "Investigate the alerts and logs, classify the severity, take appropriate "
        "remediation action, and submit a final incident report."
    ),
    # ------------------------------------------------------------------
    # Initial alerts (3 malicious + 1 benign decoy)
    # ------------------------------------------------------------------
    initial_alerts=[
        Alert(
            id="alert-001",
            timestamp="2025-01-15T03:22:11Z",
            source="ssh-monitor",
            severity="High",
            message=(
                "Multiple failed SSH login attempts detected from 198.51.100.23 "
                "to host web-server-01 (port 22)"
            ),
        ),
        Alert(
            id="alert-002",
            timestamp="2025-01-15T03:28:45Z",
            source="ssh-monitor",
            severity="High",
            message=(
                "Continued SSH brute-force activity from 198.51.100.23 against "
                "web-server-01 — 47 failed attempts in the last 10 minutes"
            ),
        ),
        Alert(
            id="alert-003",
            timestamp="2025-01-15T03:34:02Z",
            source="ssh-monitor",
            severity="High",
            message=(
                "Successful SSH login from 198.51.100.23 to web-server-01 as "
                "user 'admin' after 63 failed attempts"
            ),
        ),
        Alert(
            id="alert-004",
            timestamp="2025-01-15T03:25:30Z",
            source="app-monitor",
            severity="Low",
            message=(
                "Routine health-check timeout on app-server-01 — recovered "
                "after 2 seconds"
            ),
        ),
    ],
    # ------------------------------------------------------------------
    # Initial logs (6 auth log entries)
    # ------------------------------------------------------------------
    initial_logs=[
        LogEntry(
            timestamp="2025-01-15T03:20:05Z",
            source="auth-logs",
            level="INFO",
            content=(
                "sshd[4821]: Failed password for root from 198.51.100.23 "
                "port 44210 ssh2"
            ),
        ),
        LogEntry(
            timestamp="2025-01-15T03:21:18Z",
            source="auth-logs",
            level="INFO",
            content=(
                "sshd[4821]: Failed password for admin from 198.51.100.23 "
                "port 44211 ssh2"
            ),
        ),
        LogEntry(
            timestamp="2025-01-15T03:23:42Z",
            source="auth-logs",
            level="WARNING",
            content=(
                "sshd[4821]: Failed password for deploy from 198.51.100.23 "
                "port 44215 ssh2"
            ),
        ),
        LogEntry(
            timestamp="2025-01-15T03:26:09Z",
            source="auth-logs",
            level="WARNING",
            content=(
                "sshd[4821]: Failed password for ubuntu from 198.51.100.23 "
                "port 44220 ssh2"
            ),
        ),
        LogEntry(
            timestamp="2025-01-15T03:30:55Z",
            source="auth-logs",
            level="WARNING",
            content=(
                "sshd[4821]: Failed password for admin from 198.51.100.23 "
                "port 44233 ssh2"
            ),
        ),
        LogEntry(
            timestamp="2025-01-15T03:34:01Z",
            source="auth-logs",
            level="CRITICAL",
            content=(
                "sshd[4821]: Accepted password for admin from 198.51.100.23 "
                "port 44240 ssh2"
            ),
        ),
    ],
    # ------------------------------------------------------------------
    # System status
    # ------------------------------------------------------------------
    system_status={
        "web-server-01": "degraded",
        "app-server-01": "operational",
        "db-server-01": "operational",
    },
    # ------------------------------------------------------------------
    # Network topology
    # ------------------------------------------------------------------
    network_topology={
        "web-server-01": ["app-server-01"],
        "app-server-01": ["web-server-01", "db-server-01"],
        "db-server-01": ["app-server-01"],
    },
    # ------------------------------------------------------------------
    # Valid investigation / remediation targets
    # ------------------------------------------------------------------
    valid_components={
        "web-server-01",
        "app-server-01",
        "db-server-01",
        "ssh-monitor",
        "auth-logs",
        "firewall",
    },
    # ------------------------------------------------------------------
    # Ground truth
    # ------------------------------------------------------------------
    ground_truth=GroundTruth(
        severity="High",
        malicious_ips=["198.51.100.23"],
        compromised_hosts=["web-server-01"],
        compromised_accounts=["admin"],
        attack_method="ssh_brute_force",
        exfil_destination=None,
        correlated_alert_groups=[["alert-001", "alert-002", "alert-003"]],
        correct_remediations=[
            {
                "action_type": "remediate",
                "target": "firewall",
                "params": {"action": "block_ip", "ip": "198.51.100.23"},
            }
        ],
        incorrect_remediations=[
            {
                "action_type": "remediate",
                "target": "web-server-01",
                "params": {"action": "shutdown"},
            }
        ],
        report_required_fields={
            "source_ip": "198.51.100.23",
            "severity": "High",
            "attack_type": "ssh_brute_force",
            "remediation": "block_ip",
        },
    ),
    # ------------------------------------------------------------------
    # Investigable sources — hidden logs revealed on investigate
    # ------------------------------------------------------------------
    investigable_sources={
        "ssh-monitor": [
            LogEntry(
                timestamp="2025-01-15T03:22:15Z",
                source="ssh-monitor",
                level="INFO",
                content=(
                    "SSH connection opened from 198.51.100.23:44210 to "
                    "web-server-01:22 — key exchange: curve25519-sha256"
                ),
            ),
            LogEntry(
                timestamp="2025-01-15T03:28:50Z",
                source="ssh-monitor",
                level="WARNING",
                content=(
                    "Rate limit threshold exceeded: 47 SSH auth failures from "
                    "198.51.100.23 in 600s window"
                ),
            ),
            LogEntry(
                timestamp="2025-01-15T03:34:03Z",
                source="ssh-monitor",
                level="CRITICAL",
                content=(
                    "SSH session established — 198.51.100.23 -> web-server-01 "
                    "user=admin PID=4821 — post brute-force success"
                ),
            ),
        ],
        "auth-logs": [
            LogEntry(
                timestamp="2025-01-15T03:34:05Z",
                source="auth-logs",
                level="INFO",
                content=(
                    "pam_unix(sshd:session): session opened for user admin "
                    "by (uid=0)"
                ),
            ),
            LogEntry(
                timestamp="2025-01-15T03:35:12Z",
                source="auth-logs",
                level="WARNING",
                content=(
                    "sudo: admin : TTY=pts/0 ; PWD=/root ; USER=root ; "
                    "COMMAND=/bin/bash"
                ),
            ),
            LogEntry(
                timestamp="2025-01-15T03:36:48Z",
                source="auth-logs",
                level="WARNING",
                content=(
                    "admin logged in from 198.51.100.23 — privilege escalation "
                    "detected: uid changed from 1000 to 0"
                ),
            ),
        ],
        "firewall": [
            LogEntry(
                timestamp="2025-01-15T03:20:02Z",
                source="firewall",
                level="INFO",
                content=(
                    "ACCEPT IN=eth0 SRC=198.51.100.23 DST=10.0.1.10 "
                    "PROTO=TCP DPT=22 — new connection"
                ),
            ),
            LogEntry(
                timestamp="2025-01-15T03:34:00Z",
                source="firewall",
                level="INFO",
                content=(
                    "ACCEPT IN=eth0 SRC=198.51.100.23 DST=10.0.1.10 "
                    "PROTO=TCP DPT=22 — established session"
                ),
            ),
        ],
    },
    # ------------------------------------------------------------------
    # Rubric weights
    # ------------------------------------------------------------------
    rubric_weights={
        "investigation": 0.2,
        "classification": 0.2,
        "remediation": 0.3,
        "report": 0.3,
    },
)

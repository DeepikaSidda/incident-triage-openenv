"""Hard scenario: Insider data exfiltration via cloud storage.

A compromised insider account (mjohnson) is exfiltrating sensitive customer
records to an external cloud storage service.  The challenge is distinguishing
legitimate activity from malicious — several alerts are genuine false positives
triggered by routine DLP rules, while the real exfiltration is buried among
normal-looking access patterns.  The agent must investigate, correlate the true
positives, remediate precisely (without disrupting innocent users), and file a
comprehensive report.
"""

from models import Alert, GroundTruth, LogEntry, TaskDefinition

TASK = TaskDefinition(
    name="insider_data_exfil",
    difficulty="hard",
    max_steps=35,
    description=(
        "A compromised insider account (mjohnson) is exfiltrating sensitive "
        "customer data to an external cloud storage service. Multiple DLP "
        "alerts have fired, but several are false positives from routine "
        "business activity. Investigate all alerts and logs, distinguish "
        "true threats from benign activity, identify the compromised account "
        "and exfiltration method, apply precise remediation without "
        "disrupting legitimate users, and submit a final incident report."
    ),
    # ------------------------------------------------------------------
    # Initial alerts (3 false positives + 4 true positives + 1 benign decoy)
    # ------------------------------------------------------------------
    initial_alerts=[
        # FALSE POSITIVE — jsmith monthly report download
        Alert(
            id="alert-de-001",
            timestamp="2025-01-15T09:12:44Z",
            source="dlp-monitor",
            severity="Medium",
            message=(
                "Large file download detected: user jsmith downloaded "
                "'Q4-Sales-Report-Final.xlsx' (48 MB) from file-server-01 "
                "— flagged by DLP policy for sensitive keyword match"
            ),
        ),
        # FALSE POSITIVE — automated backup alert
        Alert(
            id="alert-de-002",
            timestamp="2025-01-15T09:30:15Z",
            source="dlp-monitor",
            severity="Low",
            message=(
                "Scheduled backup job transferred 12.4 GB from db-server-01 "
                "to backup-vault — DLP flagged due to volume threshold "
                "exceeded (routine nightly backup running late)"
            ),
        ),
        # TRUE POSITIVE — mjohnson cloud storage upload
        Alert(
            id="alert-de-003",
            timestamp="2025-01-15T10:17:33Z",
            source="dlp-monitor",
            severity="High",
            message=(
                "Outbound file upload detected: user mjohnson uploaded "
                "'customer_records_export.csv' (127 MB) to external "
                "destination https://cloud-storage.example.com/uploads "
                "via proxy-server-01"
            ),
        ),
        # TRUE POSITIVE — unusual database queries by mjohnson
        Alert(
            id="alert-de-004",
            timestamp="2025-01-15T09:48:21Z",
            source="db-audit-logs",
            severity="High",
            message=(
                "Unusual query pattern: user mjohnson executed SELECT * "
                "on customers, payment_methods, and addresses tables in "
                "rapid succession from app-server-01 — 340,000 rows "
                "returned in 3 minutes"
            ),
        ),
        # TRUE POSITIVE — after-hours access by mjohnson
        Alert(
            id="alert-de-005",
            timestamp="2025-01-15T11:52:07Z",
            source="app-access-logs",
            severity="Medium",
            message=(
                "After-hours VPN login: user mjohnson authenticated to "
                "app-server-01 at 06:52 local time (3 hours before normal "
                "shift start) — accessed customer data export module"
            ),
        ),
        # TRUE POSITIVE — large outbound transfer to external IP
        Alert(
            id="alert-de-006",
            timestamp="2025-01-15T10:34:58Z",
            source="network-flows",
            severity="High",
            message=(
                "Large outbound data transfer: 142 MB sent from "
                "proxy-server-01 to 203.0.113.50:443 over 8 minutes — "
                "destination resolves to cloud-storage.example.com"
            ),
        ),
        # FALSE POSITIVE — routine large email attachment
        Alert(
            id="alert-de-007",
            timestamp="2025-01-15T09:55:30Z",
            source="dlp-monitor",
            severity="Medium",
            message=(
                "Large email attachment: user klee sent email with 22 MB "
                "attachment 'Project-Roadmap-2025.pptx' to external "
                "partner via mail-server-01 — flagged by outbound size "
                "policy"
            ),
        ),
        # BENIGN DECOY — system maintenance
        Alert(
            id="alert-de-008",
            timestamp="2025-01-15T08:45:00Z",
            source="app-monitor",
            severity="Low",
            message=(
                "Scheduled maintenance window: app-server-01 restarted "
                "application pool at 08:45 — all services recovered "
                "within 30 seconds, no user impact"
            ),
        ),
    ],
    # ------------------------------------------------------------------
    # Initial logs (10 entries — mix of normal and suspicious activity)
    # ------------------------------------------------------------------
    initial_logs=[
        # Normal — jsmith routine work
        LogEntry(
            timestamp="2025-01-15T09:10:02Z",
            source="app-access-logs",
            level="INFO",
            content=(
                "file-server-01 user jsmith accessed /reports/Q4-Sales-Report-Final.xlsx "
                "— monthly sales report download (authorized, role=sales-manager)"
            ),
        ),
        # Normal — klee routine work
        LogEntry(
            timestamp="2025-01-15T09:52:18Z",
            source="app-access-logs",
            level="INFO",
            content=(
                "mail-server-01 user klee sent email to partner@vendor.example.com "
                "with attachment Project-Roadmap-2025.pptx (22 MB) — outbound "
                "email within policy"
            ),
        ),
        # Suspicious — mjohnson early VPN login
        LogEntry(
            timestamp="2025-01-15T06:51:44Z",
            source="app-access-logs",
            level="WARNING",
            content=(
                "app-server-01 VPN authentication: user mjohnson logged in "
                "from IP 192.168.1.105 at 06:51 — outside normal business "
                "hours (shift starts 10:00)"
            ),
        ),
        # Suspicious — mjohnson database query (customers)
        LogEntry(
            timestamp="2025-01-15T09:45:11Z",
            source="db-audit-logs",
            level="WARNING",
            content=(
                "db-server-01 query by mjohnson@app-server-01: "
                "SELECT * FROM customers WHERE region IN ('NA','EU') "
                "— 185,000 rows returned, execution time 42s"
            ),
        ),
        # Suspicious — mjohnson database query (payment_methods)
        LogEntry(
            timestamp="2025-01-15T09:46:38Z",
            source="db-audit-logs",
            level="WARNING",
            content=(
                "db-server-01 query by mjohnson@app-server-01: "
                "SELECT * FROM payment_methods WHERE customer_id IN "
                "(SELECT id FROM customers WHERE region IN ('NA','EU')) "
                "— 112,000 rows returned, execution time 38s"
            ),
        ),
        # Suspicious — mjohnson database query (addresses)
        LogEntry(
            timestamp="2025-01-15T09:47:55Z",
            source="db-audit-logs",
            level="WARNING",
            content=(
                "db-server-01 query by mjohnson@app-server-01: "
                "SELECT * FROM addresses WHERE customer_id IN "
                "(SELECT id FROM customers WHERE region IN ('NA','EU')) "
                "— 43,000 rows returned, execution time 15s"
            ),
        ),
        # Suspicious — mjohnson cloud storage upload
        LogEntry(
            timestamp="2025-01-15T10:15:22Z",
            source="network-flows",
            level="WARNING",
            content=(
                "proxy-server-01 HTTPS POST: user mjohnson -> "
                "https://cloud-storage.example.com/uploads "
                "— 127 MB payload, content-type multipart/form-data, "
                "file customer_records_export.csv"
            ),
        ),
        # Suspicious — outbound transfer to external destination
        LogEntry(
            timestamp="2025-01-15T10:33:40Z",
            source="network-flows",
            level="WARNING",
            content=(
                "proxy-server-01 sustained outbound transfer to "
                "203.0.113.50:443 (cloud-storage.example.com) — "
                "142 MB over 480 seconds, TLS 1.3 encrypted"
            ),
        ),
        # Normal — automated backup
        LogEntry(
            timestamp="2025-01-15T09:28:05Z",
            source="app-access-logs",
            level="INFO",
            content=(
                "db-server-01 scheduled backup job svc-backup started — "
                "full database dump to /mnt/backup-vault, expected "
                "duration 45 minutes"
            ),
        ),
        # Normal — system maintenance
        LogEntry(
            timestamp="2025-01-15T08:45:02Z",
            source="app-access-logs",
            level="INFO",
            content=(
                "app-server-01 application pool recycled during scheduled "
                "maintenance window — all worker processes restarted, "
                "health check passed at 08:45:30"
            ),
        ),
    ],
    # ------------------------------------------------------------------
    # System status
    # ------------------------------------------------------------------
    system_status={
        "db-server-01": "operational",
        "app-server-01": "operational",
        "file-server-01": "operational",
        "mail-server-01": "operational",
        "proxy-server-01": "operational",
    },
    # ------------------------------------------------------------------
    # Network topology
    # ------------------------------------------------------------------
    network_topology={
        "db-server-01": ["app-server-01"],
        "app-server-01": ["db-server-01", "file-server-01", "proxy-server-01"],
        "file-server-01": ["app-server-01"],
        "mail-server-01": ["proxy-server-01"],
        "proxy-server-01": ["app-server-01", "mail-server-01"],
    },
    # ------------------------------------------------------------------
    # Valid investigation / remediation targets
    # ------------------------------------------------------------------
    valid_components={
        "db-server-01",
        "app-server-01",
        "file-server-01",
        "mail-server-01",
        "proxy-server-01",
        "dlp-monitor",
        "db-audit-logs",
        "app-access-logs",
        "network-flows",
        "hr-system",
    },
    # ------------------------------------------------------------------
    # Ground truth
    # ------------------------------------------------------------------
    ground_truth=GroundTruth(
        severity="Critical",
        malicious_ips=[],
        compromised_hosts=[],
        compromised_accounts=["mjohnson"],
        attack_method="insider_data_exfiltration_via_cloud_storage",
        exfil_destination="https://cloud-storage.example.com/uploads",
        correlated_alert_groups=[
            ["alert-de-003", "alert-de-004", "alert-de-005"],
            ["alert-de-006"],
        ],
        correct_remediations=[
            {
                "action_type": "remediate",
                "target": "app-access-logs",
                "params": {
                    "action": "revoke_credentials",
                    "account": "mjohnson",
                },
            },
            {
                "action_type": "remediate",
                "target": "proxy-server-01",
                "params": {
                    "action": "block_domain",
                    "domain": "cloud-storage.example.com",
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
                "target": "app-access-logs",
                "params": {
                    "action": "revoke_credentials",
                    "account": "jsmith",
                },
            },
            {
                "action_type": "remediate",
                "target": "mail-server-01",
                "params": {"action": "isolate_host"},
            },
        ],
        report_required_fields={
            "compromised_account": "mjohnson",
            "exfil_method": "cloud_storage_upload",
            "exfil_destination": "cloud-storage.example.com",
            "data_affected": "customer_records",
            "severity": "Critical",
        },
    ),
    # ------------------------------------------------------------------
    # Investigable sources — hidden logs revealed on investigate
    # ------------------------------------------------------------------
    investigable_sources={
        "dlp-monitor": [
            LogEntry(
                timestamp="2025-01-15T09:13:01Z",
                source="dlp-monitor",
                level="INFO",
                content=(
                    "DLP policy match detail: jsmith download of "
                    "Q4-Sales-Report-Final.xlsx matched keyword 'revenue' "
                    "— file originated from /reports/ share, user has "
                    "sales-manager role with read access (authorized)"
                ),
            ),
            LogEntry(
                timestamp="2025-01-15T10:18:05Z",
                source="dlp-monitor",
                level="CRITICAL",
                content=(
                    "DLP policy match detail: mjohnson upload of "
                    "customer_records_export.csv to external URL "
                    "https://cloud-storage.example.com/uploads — file "
                    "contains PII fields (name, email, address, payment_token), "
                    "user does NOT have data-export role"
                ),
            ),
            LogEntry(
                timestamp="2025-01-15T09:56:12Z",
                source="dlp-monitor",
                level="INFO",
                content=(
                    "DLP policy match detail: klee outbound email attachment "
                    "Project-Roadmap-2025.pptx matched size threshold — "
                    "recipient partner@vendor.example.com is on approved "
                    "external contacts list, no PII detected"
                ),
            ),
        ],
        "db-audit-logs": [
            LogEntry(
                timestamp="2025-01-15T09:44:50Z",
                source="db-audit-logs",
                level="WARNING",
                content=(
                    "db-server-01 session opened by mjohnson@app-server-01 "
                    "— client application: python3/psycopg2 (not the "
                    "standard internal reporting tool), source IP 10.0.2.20"
                ),
            ),
            LogEntry(
                timestamp="2025-01-15T09:48:30Z",
                source="db-audit-logs",
                level="CRITICAL",
                content=(
                    "db-server-01 bulk export detected: mjohnson exported "
                    "340,000 rows from customers+payment_methods+addresses "
                    "to CSV via COPY command — total export size 127 MB, "
                    "no prior export history for this account"
                ),
            ),
        ],
        "app-access-logs": [
            LogEntry(
                timestamp="2025-01-15T06:52:10Z",
                source="app-access-logs",
                level="WARNING",
                content=(
                    "app-server-01 mjohnson accessed /admin/data-export "
                    "endpoint at 06:52 — this endpoint is restricted to "
                    "data-admin role; mjohnson role is analyst (insufficient "
                    "privilege, request succeeded due to misconfigured ACL)"
                ),
            ),
            LogEntry(
                timestamp="2025-01-15T10:12:44Z",
                source="app-access-logs",
                level="WARNING",
                content=(
                    "app-server-01 mjohnson initiated bulk download of "
                    "customer_records_export.csv (127 MB) from local "
                    "staging directory /tmp/exports/ — file created 3 "
                    "minutes prior by same user session"
                ),
            ),
        ],
        "network-flows": [
            LogEntry(
                timestamp="2025-01-15T10:14:55Z",
                source="network-flows",
                level="WARNING",
                content=(
                    "proxy-server-01 new HTTPS connection: "
                    "10.0.2.20 (app-server-01) -> 203.0.113.50:443 "
                    "(cloud-storage.example.com) — user-agent: "
                    "python-requests/2.31.0, not a standard browser"
                ),
            ),
            LogEntry(
                timestamp="2025-01-15T10:35:20Z",
                source="network-flows",
                level="CRITICAL",
                content=(
                    "proxy-server-01 connection summary: mjohnson session "
                    "transferred 142 MB outbound to cloud-storage.example.com "
                    "across 2 HTTPS POST requests — destination not on "
                    "approved external services list"
                ),
            ),
        ],
        "hr-system": [
            LogEntry(
                timestamp="2025-01-15T08:00:00Z",
                source="hr-system",
                level="INFO",
                content=(
                    "Employee record: mjohnson (Michael Johnson), role=analyst, "
                    "department=Business Intelligence, hire_date=2022-03-14, "
                    "status=active, manager=dthompson"
                ),
            ),
            LogEntry(
                timestamp="2025-01-14T16:30:00Z",
                source="hr-system",
                level="WARNING",
                content=(
                    "HR flag: mjohnson submitted resignation notice on "
                    "2025-01-14, last working day 2025-01-28 — account "
                    "scheduled for deprovisioning on departure date"
                ),
            ),
        ],
    },
    # ------------------------------------------------------------------
    # Rubric weights
    # ------------------------------------------------------------------
    rubric_weights={
        "investigation": 0.20,
        "classification": 0.10,
        "correlation": 0.15,
        "remediation": 0.25,
        "report": 0.20,
        "precision": 0.10,
    },
)

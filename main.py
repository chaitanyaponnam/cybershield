from collections import Counter

from core.security_engine import SecurityEngine
from core.incident_manager import IncidentManager

from services.file_manager import FileManager
from services.report_generator import ReportGenerator
from services.log_history import LogHistory
from services.event_timeline import EventTimeline
from services.evidence_correlator import EvidenceCorrelator
from services.evidence_integrity import EvidenceIntegrity
from services.audit_trail import AuditTrail
from services.dashboard_analytics import DashboardAnalytics
from services.incident_filter import IncidentFilter
from services.risk_scorer import RiskScorer


class SOCDashboard:

    def __init__(self):
        self.engine = SecurityEngine()
        self.manager = IncidentManager()

    def get_incidents(self):
        return list(self.manager.incidents.values())

    @staticmethod
    def get_incident_statistics(incidents):
        severity_counts = {
            level: 0
            for level in (
                "LOW",
                "MEDIUM",
                "HIGH",
                "CRITICAL"
            )
        }

        status_counts = {
            status: 0
            for status in (
                "OPEN",
                "INVESTIGATING",
                "RESOLVED"
            )
        }

        tracked_event_ids = set()
        brute_force_incidents = 0
        legacy_login_alerts = 0

        for incident in incidents:
            if incident.severity in severity_counts:
                severity_counts[incident.severity] += 1

            if incident.status in status_counts:
                status_counts[incident.status] += 1

            has_brute_force_alert = False

            for alert in incident.alerts:
                if alert.threat_type != "Potential Brute Force":
                    continue

                has_brute_force_alert = True

                event_ids = getattr(
                    alert,
                    "event_ids",
                    []
                )

                if event_ids:
                    tracked_event_ids.update(event_ids)
                else:
                    legacy_login_alerts += 1

            if has_brute_force_alert:
                brute_force_incidents += 1

        return {
            "total_incidents": len(incidents),
            "severity": severity_counts,
            "status": status_counts,
            "brute_force_incidents": brute_force_incidents,
            "unique_tracked_login_events": len(
                tracked_event_ids
            ),
            "legacy_login_alerts": legacy_login_alerts
        }

    def display_menu(self):
        print("\n" + "=" * 45)
        print("       CYBERSHIELD - MINI SOC")
        print("=" * 45)
        print("1. Run Security Scan")
        print("2. View Security Incidents")
        print("3. Investigate an Incident")
        print("4. View Latest Security Report")
        print("5. View Incident Statistics")
        print("6. Add Investigation Note")
        print("7. Export Incident Report")
        print("8. View SOC Event Timeline")
        print("9. Verify Exported Report")
        print("10. View Evidence Audit Trail")
        print("11. View SOC Dashboard")
        print("12. Incident Search & Filtering")
        print("13. Incident Risk Priority")
        print("14. Exit")
        print("=" * 45)

    def scan_menu(self):
        print("\n===== SECURITY SCAN =====")
        print("1. Scan existing saved logs")
        print("2. Generate new logs and scan")
        print("3. Cancel")

        choice = input(
            "Select an option: "
        ).strip()

        if choice == "1":
            self.run_scan()

        elif choice == "2":
            result = LogHistory.generate_and_save()

            print(
                "\nGenerated events:",
                result["generated"]
            )

            print(
                "New events saved:",
                result["added"]
            )

            print(
                "Total saved login events:",
                result["total"]
            )

            self.run_scan()

        elif choice == "3":
            print("Scan cancelled.")

        else:
            print("Invalid choice.")

    def run_scan(self):
        previous_ids = {
            incident.incident_id
            for incident in self.get_incidents()
        }

        alerts = self.engine.run_scan()

        incidents = self.manager.correlate(
            alerts
        )

        self.manager.save_incidents()

        new_incidents = [
            incident
            for incident in incidents
            if incident.incident_id not in previous_ids
        ]

        threat_counts = Counter(
            alert.threat_type
            for alert in alerts
        )

        print("\n===== SCAN SUMMARY =====")
        print("Scan completed!")

        print(
            f"Detected alerts: {len(alerts)}"
        )

        print(
            f"New incidents: {len(new_incidents)}"
        )

        print(
            "Total tracked incidents:",
            len(incidents)
        )

        print("\nDetected threat types:")

        if not threat_counts:
            print("No threats detected.")

        else:
            for threat_type, count in sorted(
                threat_counts.items()
            ):
                print(
                    f"  {threat_type}: {count}"
                )

        statistics = self.get_incident_statistics(
            incidents
        )

        print(
            "\nUnique tracked failed-login events:",
            statistics["unique_tracked_login_events"]
        )

    def view_incidents(self):
        incidents = self.get_incidents()

        if not incidents:
            print("\nNo incidents found.")
            return

        print("\n===== SECURITY INCIDENTS =====")

        for incident in incidents:
            incident.display()

            login_alerts = [
                alert
                for alert in incident.alerts
                if alert.threat_type
                == "Potential Brute Force"
            ]

            if not login_alerts:
                continue

            event_ids = {
                event_id
                for alert in login_alerts
                for event_id in getattr(
                    alert,
                    "event_ids",
                    []
                )
            }

            print(
                "Unique tracked login events:",
                len(event_ids)
            )

            if any(
                not getattr(
                    alert,
                    "event_ids",
                    []
                )
                for alert in login_alerts
            ):
                print(
                    "Note: Legacy login evidence "
                    "has no event IDs."
                )

    def find_incident(self, incident_id):
        return next(
            (
                incident
                for incident in self.get_incidents()
                if incident.incident_id == incident_id
            ),
            None
        )

    def show_attack_details(self, incident):
        print("\n===== ATTACK EVIDENCE =====")

        found = False

        for alert in incident.alerts:
            if alert.threat_type != "Potential Brute Force":
                continue

            found = True

            print(
                f"\nSource IP: {alert.source_ip}"
            )

            attack_window = (
                self.manager.get_attack_window(
                    alert
                )
            )

            if attack_window:
                start, end = attack_window

                print(
                    "Attack start:",
                    start.isoformat()
                )

                print(
                    "Attack end:",
                    end.isoformat()
                )

            event_ids = getattr(
                alert,
                "event_ids",
                []
            )

            if event_ids:
                print(
                    "Unique tracked events:",
                    len(set(event_ids))
                )

            else:
                print(
                    "Exact event count: unavailable "
                    "(legacy evidence)"
                )

            print(
                f"Finding: {alert.description}"
            )

        if not found:
            print(
                "No brute-force evidence "
                "in this incident."
            )

    def investigate_incident(self):
        self.view_incidents()

        if not self.manager.incidents:
            return

        incident_id = input(
            "\nEnter Incident ID: "
        ).strip()

        selected = self.find_incident(
            incident_id
        )

        if selected is None:
            print("Incident not found!")
            return

        print("\n===== INCIDENT DETAILS =====")

        selected.display()

        self.show_attack_details(
            selected
        )

        print(
            "\n===== INVESTIGATION NOTES ====="
        )

        if not selected.notes:
            print(
                "No investigation notes yet."
            )

        for note in selected.notes:
            print(
                f"\nAnalyst: {note['analyst']}"
            )

            print(
                f"Time: {note['timestamp']}"
            )

            print(
                f"Note: {note['message']}"
            )

        print("\n===== RELATED ALERTS =====")

        for alert in selected.alerts:
            alert.display()

        while True:
            print(
                "\n===== INVESTIGATION ACTIONS ====="
            )

            print("1. Mark OPEN")
            print("2. Mark INVESTIGATING")
            print("3. Mark RESOLVED")
            print("4. View Login Evidence")
            print("5. Return to Main Menu")

            choice = input(
                "Select an option: "
            ).strip()

            if choice == "4":
                result = (
                    EvidenceCorrelator.find_evidence(
                        selected,
                        self.manager
                    )
                )

                EvidenceCorrelator.display(
                    result
                )

                continue

            if choice == "5":
                return

            statuses = {
                "1": "OPEN",
                "2": "INVESTIGATING",
                "3": "RESOLVED"
            }

            if choice not in statuses:
                print("Invalid choice!")
                continue

            self.manager.update_incident(
                incident_id,
                statuses[choice]
            )

            print(
                "Incident status updated."
            )

            return

    def view_report(self):
        report = FileManager.load_data(
            "security_report.json"
        )

        if not report:
            print(
                "No security report available."
            )
            return

        print(
            "\n===== LATEST SECURITY REPORT ====="
        )

        print(
            "Scan time:",
            report.get(
                "scan_time",
                "Unknown"
            )
        )

        print(
            "Total alerts:",
            report.get(
                "total_alerts",
                0
            )
        )

        threat_counts = Counter()

        for alert in report.get(
            "alerts",
            []
        ):
            severity = alert.get(
                "severity",
                "UNKNOWN"
            )

            threat_type = alert.get(
                "threat_type",
                "Unknown Threat"
            )

            print(
                f"[{severity}] {threat_type}"
            )

            threat_counts[threat_type] += 1

        print(
            "\n===== THREAT SUMMARY ====="
        )

        if not threat_counts:
            print(
                "No threats in the latest report."
            )

        else:
            for threat_type, count in sorted(
                threat_counts.items()
            ):
                print(
                    f"{threat_type}: {count}"
                )

    def view_statistics(self):
        statistics = (
            self.get_incident_statistics(
                self.get_incidents()
            )
        )

        print(
            "\n===== SOC STATISTICS ====="
        )

        print(
            "Total incidents:",
            statistics["total_incidents"]
        )

        print("\n===== BY SEVERITY =====")

        for severity, count in (
            statistics["severity"].items()
        ):
            print(
                f"{severity}: {count}"
            )

        print("\n===== BY STATUS =====")

        for status, count in (
            statistics["status"].items()
        ):
            print(
                f"{status}: {count}"
            )

        print("\n===== LOGIN THREATS =====")

        print(
            "Brute-force incidents:",
            statistics["brute_force_incidents"]
        )

        print(
            "Unique tracked failed-login events:",
            statistics["unique_tracked_login_events"]
        )

        if statistics["legacy_login_alerts"]:
            print(
                "Legacy login alerts without IDs:",
                statistics["legacy_login_alerts"]
            )

            print(
                "Historical event totals may be "
                "higher than the tracked count."
            )

    # ============================================================
    # PHASE 27 - SOC DASHBOARD
    # ============================================================

    def view_soc_dashboard(self):
        incidents = self.get_incidents()

        analytics = DashboardAnalytics.calculate(
            incidents
        )

        print("\n" + "=" * 60)
        print("              CYBERSHIELD SOC DASHBOARD")
        print("=" * 60)

        print("\nINCIDENT OVERVIEW")
        print("-" * 60)

        print(
            f"Total Incidents       : "
            f"{analytics['total_incidents']}"
        )

        print(
            f"Total Alerts          : "
            f"{analytics['total_alerts']}"
        )

        print("\nSTATUS")
        print("-" * 60)

        for status in (
            "OPEN",
            "INVESTIGATING",
            "RESOLVED"
        ):
            count = DashboardAnalytics.get_status_count(
                analytics,
                status
            )

            print(
                f"{status:<22}: {count}"
            )

        print("\nSEVERITY")
        print("-" * 60)

        for severity in (
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW"
        ):
            count = DashboardAnalytics.get_severity_count(
                analytics,
                severity
            )

            print(
                f"{severity:<22}: {count}"
            )

        print("\nTOP THREAT TYPES")
        print("-" * 60)

        top_threats = DashboardAnalytics.top_threats(
            analytics
        )

        if not top_threats:
            print("No threat data available.")
        else:
            for threat_type, count in top_threats:
                print(
                    f"{threat_type:<35}: {count}"
                )

        print("\nTOP SOURCE IPS")
        print("-" * 60)

        top_source_ips = DashboardAnalytics.top_source_ips(
            analytics
        )

        if not top_source_ips:
            print("No source IP data available.")
        else:
            for source_ip, count in top_source_ips:
                print(
                    f"{source_ip:<35}: {count}"
                )

        print("=" * 60)

        def incident_search_and_filter(self):
            while True:
                print("\n" + "=" * 45)
                print("      INCIDENT SEARCH & FILTER")
                print("=" * 45)
    
                print("1. Filter by Severity")
                print("2. Filter by Status")
                print("3. Filter by Threat Type")
                print("4. Filter by Source IP")
                print("5. Search by Incident ID")
                print("6. Show All Incidents")
                print("7. Back")
    
                print("=" * 45)
    
                choice = input(
                    "Select an option: "
                ).strip()
    
                incidents = self.get_incidents()
    
                if choice == "1":
                    severity = input(
                        "Enter severity "
                        "(LOW/MEDIUM/HIGH/CRITICAL): "
                    ).strip()
    
                    results = IncidentFilter.by_severity(
                        incidents,
                        severity
                    )
    
                    self.display_filtered_incidents(results)
    
                elif choice == "2":
                    status = input(
                        "Enter status "
                        "(OPEN/INVESTIGATING/RESOLVED): "
                    ).strip()
    
                    results = IncidentFilter.by_status(
                        incidents,
                        status
                    )
    
                    self.display_filtered_incidents(results)
    
                elif choice == "3":
                    threat_type = input(
                        "Enter threat type: "
                    ).strip()
    
                    results = IncidentFilter.by_threat_type(
                        incidents,
                        threat_type
                    )
    
                    self.display_filtered_incidents(results)
    
                elif choice == "4":
                    source_ip = input(
                        "Enter source IP: "
                    ).strip()
    
                    results = IncidentFilter.by_source_ip(
                        incidents,
                        source_ip
                    )
    
                    self.display_filtered_incidents(results)
    
                elif choice == "5":
                    incident_id = input(
                        "Enter Incident ID: "
                    ).strip()
    
                    results = IncidentFilter.by_incident_id(
                        incidents,
                        incident_id
                    )
    
                    self.display_filtered_incidents(results)
    
                elif choice == "6":
                    self.display_filtered_incidents(
                        incidents
                    )
    
                elif choice == "7":
                    return
                
    
                else:
                    print("Invalid choice.")


    @staticmethod
    def display_filtered_incidents(incidents):
        print("\n" + "=" * 60)
        print("              FILTERED INCIDENTS")
        print("=" * 60)

        if not incidents:
            print("No matching incidents found.")
            print("=" * 60)
            return

        for incident in incidents:
            print(
                f"\nIncident ID : "
                f"{incident.incident_id}"
            )

            print(
                f"Title       : "
                f"{incident.title}"
            )

            print(
                f"Severity    : "
                f"{incident.severity}"
            )

            print(
                f"Status      : "
                f"{incident.status}"
            )

            print(
                f"Alerts      : "
                f"{len(incident.alerts)}"
            )

            print("-" * 60)

        print(
            f"Total Matches: {len(incidents)}"
        )

        print("=" * 60)

    def add_investigation_note(self):
        self.view_incidents()

        if not self.manager.incidents:
            return

        incident_id = input(
            "\nEnter Incident ID: "
        ).strip()

        selected = self.find_incident(
            incident_id
        )

        if selected is None:
            print(
                "Incident not found!"
            )
            return

        analyst = input(
            "Analyst name: "
        ).strip()

        message = input(
            "Investigation note: "
        ).strip()

        try:
            self.manager.add_investigation_note(
                incident_id,
                analyst,
                message
            )

        except ValueError as error:
            print(error)
            return

        print(
            "Investigation note saved."
        )

    def export_incident_report(self):
        self.view_incidents()

        if not self.manager.incidents:
            return

        incident_id = input(
            "\nEnter Incident ID: "
        ).strip()

        selected = self.find_incident(
            incident_id
        )

        if selected is None:
            print(
                "Incident not found!"
            )
            return

        print("\n1. Export JSON")
        print("2. Export PDF")
        print("3. Export Both")
        print("4. Cancel")

        choice = input(
            "Select report format: "
        ).strip()

        if choice == "4":
            print(
                "Export cancelled."
            )
            return

        if choice not in (
            "1",
            "2",
            "3"
        ):
            print(
                "Invalid report format."
            )
            return

        evidence = (
            EvidenceCorrelator.find_evidence(
                selected,
                self.manager
            )
        )

        print(
            "\n===== EVIDENCE SUMMARY ====="
        )

        print(
            "Exact matches:",
            len(
                evidence["exact_matches"]
            )
        )

        print(
            "Approximate legacy matches:",
            len(
                evidence["legacy_matches"]
            )
        )

        print(
            "Missing tracked events:",
            evidence["missing_tracked_events"]
        )

        if choice in (
            "1",
            "3"
        ):
            json_path = (
                ReportGenerator.export_incident(
                    selected,
                    evidence=evidence
                )
            )

            json_manifest = (
                EvidenceIntegrity.create_manifest(
                    json_path
                )
            )

            json_hash = (
                EvidenceIntegrity.calculate_hash(
                    json_path
                )
            )

            AuditTrail.record_event(
                action="EXPORT",
                report_path=json_path,
                sha256=json_hash,
                status="CREATED",
                incident_id=selected.incident_id
            )

            print(
                f"JSON report: {json_path}"
            )

            print(
                f"SHA-256 manifest: {json_manifest}"
            )

            print(
                "Audit event recorded: EXPORT"
            )

        if choice in (
            "2",
            "3"
        ):
            pdf_path = (
                ReportGenerator.export_incident_pdf(
                    selected,
                    evidence=evidence
                )
            )

            pdf_manifest = (
                EvidenceIntegrity.create_manifest(
                    pdf_path
                )
            )

            pdf_hash = (
                EvidenceIntegrity.calculate_hash(
                    pdf_path
                )
            )

            AuditTrail.record_event(
                action="EXPORT",
                report_path=pdf_path,
                sha256=pdf_hash,
                status="CREATED",
                incident_id=selected.incident_id
            )

            print(
                f"PDF report: {pdf_path}"
            )

            print(
                f"SHA-256 manifest: {pdf_manifest}"
            )

            print(
                "Audit event recorded: EXPORT"
            )

    def view_event_timeline(self):
        print(
            "\n===== EVENT TIMELINE ====="
        )

        print(
            "1. View all login events"
        )

        print(
            "2. Filter login events"
        )

        print(
            "3. Cancel"
        )

        choice = input(
            "Select an option: "
        ).strip()

        if choice == "3":
            print(
                "Timeline cancelled."
            )
            return

        if choice == "1":
            events = EventTimeline.search()

        elif choice == "2":
            print(
                "\nLeave any filter blank "
                "to include all values."
            )

            source_ip = input(
                "Source IP: "
            ).strip()

            status = input(
                "Login status (SUCCESS/FAILED): "
            ).strip().upper()

            if status and status not in (
                "SUCCESS",
                "FAILED"
            ):
                print(
                    "Invalid login status."
                )
                return

            start_time = input(
                "Start time (ISO format): "
            ).strip()

            end_time = input(
                "End time (ISO format): "
            ).strip()

            try:
                events = EventTimeline.search(
                    source_ip=source_ip or None,
                    status=status or None,
                    start_time=start_time or None,
                    end_time=end_time or None
                )

            except ValueError as error:
                print(
                    f"Timeline error: {error}"
                )
                return

        else:
            print(
                "Invalid choice."
            )
            return

        EventTimeline.display(
            events
        )

    def verify_exported_report(self):
        print(
            "\n===== VERIFY EXPORTED REPORT ====="
        )

        report_path = input(
            "Enter JSON or PDF report path: "
        ).strip()

        if not report_path:
            print(
                "No report path provided."
            )
            return

        result = (
            EvidenceIntegrity.verify_report(
                report_path
            )
        )

        status = result["status"]

        print(
            "\nVerification status:",
            status
        )

        print(
            "Report:",
            result["report"]
        )

        sha256 = result.get(
            "actual_sha256"
        )

        AuditTrail.record_event(
            action="VERIFY",
            report_path=report_path,
            sha256=sha256,
            status=status
        )

        print(
            "Audit event recorded: VERIFY"
        )

        if status == "VERIFIED":
            print(
                "The report matches "
                "its SHA-256 manifest."
            )

            print(
                "SHA-256:",
                result["actual_sha256"]
            )

        elif status == "MODIFIED":
            print(
                "WARNING: The report no longer "
                "matches its original manifest."
            )

            print(
                "Expected SHA-256:",
                result["expected_sha256"]
            )

            print(
                "Actual SHA-256:",
                result["actual_sha256"]
            )

        elif status == "REPORT_MISSING":
            print(
                "The manifest exists, "
                "but the report is missing."
            )

        elif status == "MANIFEST_MISSING":
            print(
                "No SHA-256 manifest was found "
                "for this report."
            )

        elif status == "INVALID_MANIFEST":
            print(
                "The SHA-256 manifest is invalid "
                "or cannot be read."
            )

    def view_audit_trail(self):
        print(
            "\n===== EVIDENCE AUDIT TRAIL ====="
        )

        print(
            "1. View all audit events"
        )

        print(
            "2. Filter by action"
        )

        print(
            "3. Filter by incident ID"
        )

        print(
            "4. Return to Main Menu"
        )

        choice = input(
            "Select an option: "
        ).strip()

        if choice == "1":
            AuditTrail.display_events()

        elif choice == "2":
            print("\nAvailable actions:")
            print("1. EXPORT")
            print("2. VERIFY")

            action_choice = input(
                "Select action: "
            ).strip()

            actions = {
                "1": "EXPORT",
                "2": "VERIFY"
            }

            if action_choice not in actions:
                print("Invalid action.")
                return

            events = AuditTrail.get_events(
                action=actions[action_choice]
            )

            AuditTrail.display_events(
                events
            )

        elif choice == "3":
            incident_id = input(
                "Enter Incident ID: "
            ).strip()

            if not incident_id:
                print(
                    "Incident ID cannot be empty."
                )
                return

            events = AuditTrail.get_events(
                incident_id=incident_id
            )

            AuditTrail.display_events(
                events
            )

        elif choice == "4":
            return

        else:
            print("Invalid choice.")

    def incident_search_and_filter(self):
        while True:
            print("\n" + "=" * 45)
            print("      INCIDENT SEARCH & FILTER")
            print("=" * 45)
            print("1. Filter by Severity")
            print("2. Filter by Status")
            print("3. Filter by Threat Type")
            print("4. Filter by Source IP")
            print("5. Search by Incident ID")
            print("6. Show All Incidents")
            print("7. Back")
            print("=" * 45)
            choice = input(
                "Select an option: "
            ).strip()
            incidents = self.get_incidents()
            if choice == "1":
                severity = input(
                    "Enter severity "
                    "(LOW/MEDIUM/HIGH/CRITICAL): "
                ).strip()
                results = IncidentFilter.by_severity(
                    incidents,
                    severity
                )
                self.display_filtered_incidents(
                    results
                )
            elif choice == "2":
                status = input(
                    "Enter status "
                    "(OPEN/INVESTIGATING/RESOLVED): "
                ).strip()
                results = IncidentFilter.by_status(
                    incidents,
                    status
                )
                self.display_filtered_incidents(
                    results
                )
            elif choice == "3":
                threat_type = input(
                    "Enter threat type: "
                ).strip()
                results = IncidentFilter.by_threat_type(
                    incidents,
                    threat_type
                )
                self.display_filtered_incidents(
                    results
                )
            elif choice == "4":
                source_ip = input(
                    "Enter source IP: "
                ).strip()
                results = IncidentFilter.by_source_ip(
                    incidents,
                    source_ip
                )
                self.display_filtered_incidents(
                    results
                )
            elif choice == "5":
                incident_id = input(
                    "Enter Incident ID: "
                ).strip()
                results = IncidentFilter.by_incident_id(
                    incidents,
                    incident_id
                )
                self.display_filtered_incidents(
                    results
                )
            elif choice == "6":
                self.display_filtered_incidents(
                    incidents
                )
            elif choice == "7":
                return
            else:
                print("Invalid choice.")

    @staticmethod
    def display_filtered_incidents(incidents):
        print("\n" + "=" * 60)
        print("              FILTERED INCIDENTS")
        print("=" * 60)

        if not incidents:
            print("No matching incidents found.")
            print("=" * 60)
            return

        for incident in incidents:
            print(
                f"\nIncident ID : "
                f"{incident.incident_id}"
            )

            print(
                f"Title       : "
                f"{incident.title}"
            )

            print(
                f"Severity    : "
                f"{incident.severity}"
            )

            print(
                f"Status      : "
                f"{incident.status}"
            )

            print(
                f"Alerts      : "
                f"{len(incident.alerts)}"
            )

            print("-" * 60)

        print(
            f"Total Matches: {len(incidents)}"
        )

        print("=" * 60)

    def start(self):
        while True:
            self.display_menu()

            choice = input(
                "\nEnter your choice: "
            ).strip()

            if choice == "1":
                self.scan_menu()

            elif choice == "2":
                self.view_incidents()

            elif choice == "3":
                self.investigate_incident()

            elif choice == "4":
                self.view_report()

            elif choice == "5":
                self.view_statistics()

            elif choice == "6":
                self.add_investigation_note()

            elif choice == "7":
                self.export_incident_report()

            elif choice == "8":
                self.view_event_timeline()

            elif choice == "9":
                self.verify_exported_report()

            elif choice == "10":
                self.view_audit_trail()

            elif choice == "11":
                self.view_soc_dashboard()

            elif choice == "12":
                self.incident_search_and_filter()

            elif choice == "13":
                self.view_incident_risk()

            elif choice == "14":
                print(
                    "Exiting CyberShield..."
                )
                break

            else:
                print(
                    "Invalid choice. Try again."
                )
    def view_incident_risk(self):
        incidents = self.get_incidents()

        print("\n" + "=" * 70)
        print("                 INCIDENT RISK PRIORITY")
        print("=" * 70)

        if not incidents:
            print("No incidents available.")
            print("=" * 70)
            return

        risk_entries = []

        for incident in incidents:
            score = RiskScorer.calculate(incident)
            risk_level = RiskScorer.classify(score)

            risk_entries.append(
                (
                    incident,
                    score,
                    risk_level
                )
            )

        risk_entries.sort(
            key=lambda entry: entry[1],
            reverse=True
        )

        print(
            f"{'Incident ID':<38}"
            f"{'Score':<10}"
            f"Risk Level"
        )

        print("-" * 70)

        for incident, score, risk_level in risk_entries:
            print(
                f"{incident.incident_id:<38}"
                f"{score:<10}"
                f"{risk_level}"
            )

        print("-" * 70)
        print(
            f"Total Incidents: "
            f"{len(risk_entries)}"
        )
        print("=" * 70)


if __name__ == "__main__":
    SOCDashboard().start()
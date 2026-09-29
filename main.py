
from collections import Counter

from core.security_engine import SecurityEngine
from core.incident_manager import IncidentManager
from services.file_manager import FileManager
from services.report_generator import ReportGenerator
from services.log_history import LogHistory


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
                "LOW", "MEDIUM",
                "HIGH", "CRITICAL"
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
                if (
                    alert.threat_type
                    != "Potential Brute Force"
                ):
                    continue

                has_brute_force_alert = True

                event_ids = getattr(
                    alert, "event_ids", []
                )

                if event_ids:
                    tracked_event_ids.update(
                        event_ids
                    )
                else:
                    legacy_login_alerts += 1

            if has_brute_force_alert:
                brute_force_incidents += 1

        return {
            "total_incidents": len(incidents),
            "severity": severity_counts,
            "status": status_counts,
            "brute_force_incidents": (
                brute_force_incidents
            ),
            "unique_tracked_login_events": len(
                tracked_event_ids
            ),
            "legacy_login_alerts": (
                legacy_login_alerts
            )
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
        print("8. Exit")
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
            result = (
                LogHistory.generate_and_save()
            )

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
            if incident.incident_id
            not in previous_ids
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
            f"New incidents: "
            f"{len(new_incidents)}"
        )
        print(
            "Total tracked incidents:",
            len(incidents)
        )

        print("\nDetected threat types:")

        if not threat_counts:
            print("No threats detected.")

        for threat_type, count in sorted(
            threat_counts.items()
        ):
            print(
                f"  {threat_type}: {count}"
            )

        statistics = (
            self.get_incident_statistics(
                incidents
            )
        )

        print(
            "\nUnique tracked failed-login events:",
            statistics[
                "unique_tracked_login_events"
            ]
        )

    def view_incidents(self):
        incidents = self.get_incidents()

        if not incidents:
            print("\nNo incidents found.")
            return

        print(
            "\n===== SECURITY INCIDENTS ====="
        )

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
                    alert, "event_ids", []
                )
            }

            print(
                "Unique tracked login events:",
                len(event_ids)
            )

            if any(
                not getattr(
                    alert, "event_ids", []
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
                for incident
                in self.get_incidents()
                if incident.incident_id
                == incident_id
            ),
            None
        )

    def show_attack_details(self, incident):
        print(
            "\n===== ATTACK EVIDENCE ====="
        )

        found = False

        for alert in incident.alerts:
            if (
                alert.threat_type
                != "Potential Brute Force"
            ):
                continue

            found = True

            print(
                f"\nSource IP: "
                f"{alert.source_ip}"
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
                alert, "event_ids", []
            )

            if event_ids:
                print(
                    "Unique tracked events:",
                    len(set(event_ids))
                )
            else:
                print(
                    "Exact event count: "
                    "unavailable (legacy evidence)"
                )

            print(
                f"Finding: "
                f"{alert.description}"
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

        print(
            "\n===== INCIDENT DETAILS ====="
        )
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
                f"\nAnalyst: "
                f"{note['analyst']}"
            )
            print(
                f"Time: "
                f"{note['timestamp']}"
            )
            print(
                f"Note: "
                f"{note['message']}"
            )

        print(
            "\n===== RELATED ALERTS ====="
        )

        for alert in selected.alerts:
            alert.display()

        print("\n1. Mark OPEN")
        print("2. Mark INVESTIGATING")
        print("3. Mark RESOLVED")
        print("4. Cancel")

        choice = input(
            "Select status: "
        ).strip()

        statuses = {
            "1": "OPEN",
            "2": "INVESTIGATING",
            "3": "RESOLVED"
        }

        if choice == "4":
            return

        if choice not in statuses:
            print("Invalid choice!")
            return

        self.manager.update_incident(
            incident_id,
            statuses[choice]
        )

        print(
            "Incident status updated."
        )

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
                "scan_time", "Unknown"
            )
        )

        print(
            "Total alerts:",
            report.get(
                "total_alerts", 0
            )
        )

        threat_counts = Counter()

        for alert in report.get(
            "alerts", []
        ):
            severity = alert.get(
                "severity", "UNKNOWN"
            )

            threat_type = alert.get(
                "threat_type",
                "Unknown Threat"
            )

            print(
                f"[{severity}] "
                f"{threat_type}"
            )

            threat_counts[
                threat_type
            ] += 1

        print(
            "\n===== THREAT SUMMARY ====="
        )

        if not threat_counts:
            print(
                "No threats in the latest report."
            )

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

        print(
            "\n===== BY SEVERITY ====="
        )

        for severity, count in (
            statistics["severity"].items()
        ):
            print(
                f"{severity}: {count}"
            )

        print(
            "\n===== BY STATUS ====="
        )

        for status, count in (
            statistics["status"].items()
        ):
            print(
                f"{status}: {count}"
            )

        print(
            "\n===== LOGIN THREATS ====="
        )

        print(
            "Brute-force incidents:",
            statistics[
                "brute_force_incidents"
            ]
        )

        print(
            "Unique tracked failed-login events:",
            statistics[
                "unique_tracked_login_events"
            ]
        )

        if statistics[
            "legacy_login_alerts"
        ]:
            print(
                "Legacy login alerts without IDs:",
                statistics[
                    "legacy_login_alerts"
                ]
            )

            print(
                "Historical event totals may "
                "be higher than the tracked count."
            )

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
            print("Incident not found!")
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
            print("Incident not found!")
            return

        print("\n1. Export JSON")
        print("2. Export PDF")
        print("3. Export Both")
        print("4. Cancel")

        choice = input(
            "Select report format: "
        ).strip()

        if choice in ("1", "3"):
            json_path = (
                ReportGenerator.export_incident(
                    selected
                )
            )

            print(
                f"JSON report: {json_path}"
            )

        if choice in ("2", "3"):
            pdf_path = (
                ReportGenerator.export_incident_pdf(
                    selected
                )
            )

            print(
                f"PDF report: {pdf_path}"
            )

        if choice == "4":
            print(
                "Export cancelled."
            )

        elif choice not in (
            "1", "2", "3"
        ):
            print(
                "Invalid report format."
            )

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
                print(
                    "Exiting CyberShield..."
                )
                break

            else:
                print(
                    "Invalid choice. Try again."
                )


if __name__ == "__main__":
    dashboard = SOCDashboard()
    dashboard.start()
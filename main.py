
from core.security_engine import SecurityEngine
from core.incident_manager import IncidentManager
from services.file_manager import FileManager
from services.report_generator import ReportGenerator



class SOCDashboard:

    def __init__(self):
        self.engine = SecurityEngine()
        self.manager = IncidentManager()

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

    def run_scan(self):
        alerts = self.engine.run_scan()

        incidents = self.manager.correlate(alerts)
        self.manager.save_incidents()

        print("\nScan completed!")
        print(f"Detected alerts: {len(alerts)}")
        print(f"Total tracked incidents: {len(incidents)}")

    def view_incidents(self):
        if not self.manager.incidents:
            print("\nNo incidents found.")
            return

        print("\n===== SECURITY INCIDENTS =====")

        for incident in self.manager.incidents.values():
            incident.display()

    def investigate_incident(self):
        self.view_incidents()

        if not self.manager.incidents:
            return

        incident_id = input(
            "\nEnter Incident ID: "
        ).strip()

        selected = next(
            (
                incident
                for incident in self.manager.incidents.values()
                if incident.incident_id == incident_id
            ),
            None
        )

        if selected is None:
            print("Incident not found!")
            return

        print("\n===== INCIDENT DETAILS =====")
        selected.display()

        print("\n===== INVESTIGATION NOTES =====")

        if not selected.notes:
            print("No investigation notes yet.")

        for note in selected.notes:
            print(f"\nAnalyst: {note['analyst']}")
            print(f"Time: {note['timestamp']}")
            print(f"Note: {note['message']}")

        for alert in selected.alerts:
            alert.display()

        print("\n1. Mark OPEN")
        print("2. Mark INVESTIGATING")
        print("3. Mark RESOLVED")
        print("4. Cancel")

        choice = input("Select status: ").strip()

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

        print("Incident status updated.")

    def view_report(self):
        report = FileManager.load_data(
            "security_report.json"
        )

        if not report:
            print("No security report available.")
            return

        print("\n===== LATEST SECURITY REPORT =====")
        print("Scan time:", report["scan_time"])
        print("Total alerts:", report["total_alerts"])

        for alert in report["alerts"]:
            print(
                f"[{alert['severity']}] "
                f"{alert['threat_type']}"
            )

    def view_statistics(self):
        incidents = list(
            self.manager.incidents.values()
        )

        print("\n===== SOC STATISTICS =====")
        print("Total incidents:", len(incidents))

        for status in [
            "OPEN",
            "INVESTIGATING",
            "RESOLVED"
        ]:
            count = sum(
                incident.status == status
                for incident in incidents
            )

            print(f"{status}: {count}")

    def start(self):
        while True:
            self.display_menu()

            choice = input(
                "\nEnter your choice: "
            ).strip()

            if choice == "1":
                self.run_scan()

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
                print("Exiting CyberShield...")
                break

            else:
                print("Invalid choice. Try again.")

    def add_investigation_note(self):
        self.view_incidents()

        if not self.manager.incidents:
            return

        incident_id = input(
            "\nEnter Incident ID: "
        ).strip()

        selected = next(
            (
                incident
                for incident in self.manager.incidents.values()
                if incident.incident_id == incident_id
            ),
            None
        )

        if selected is None:
            print("Incident not found!")
            return

        analyst = input("Analyst name: ").strip()
        message = input("Investigation note: ").strip()

        try:
            self.manager.add_investigation_note(
                incident_id,
                analyst,
                message
            )
        except ValueError as error:
            print(error)
            return

        print("Investigation note saved.")
    
    
    def export_incident_report(self):
        self.view_incidents()

        if not self.manager.incidents:
            return

        incident_id = input(
            "\nEnter Incident ID: "
        ).strip()

        selected = next(
            (
                incident
                for incident in self.manager.incidents.values()
                if incident.incident_id == incident_id
            ),
            None
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
            json_path = ReportGenerator.export_incident(
                selected
            )
            print(f"JSON report: {json_path}")

        if choice in ("2", "3"):
            pdf_path = ReportGenerator.export_incident_pdf(
                selected
            )
            print(f"PDF report: {pdf_path}")

        if choice == "4":
            print("Export cancelled.")

        elif choice not in ("1", "2", "3"):
            print("Invalid report format.")


if __name__ == "__main__":
    dashboard = SOCDashboard()
    dashboard.start()
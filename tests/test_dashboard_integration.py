import unittest
from contextlib import redirect_stdout
from io import StringIO
from types import SimpleNamespace
from unittest.mock import Mock, patch

from main import SOCDashboard


class TestDashboardIntegration(unittest.TestCase):

    @staticmethod
    def create_alert(threat_type, source_ip=None):
        return SimpleNamespace(
            threat_type=threat_type,
            source_ip=source_ip
        )

    @staticmethod
    def create_incident(
        severity,
        status,
        alerts
    ):
        return SimpleNamespace(
            severity=severity,
            status=status,
            alerts=alerts
        )

    def create_dashboard(self, incidents):
        dashboard = SOCDashboard.__new__(SOCDashboard)

        dashboard.manager = SimpleNamespace(
            incidents={
                str(index): incident
                for index, incident in enumerate(
                    incidents,
                    start=1
                )
            }
        )

        return dashboard

    def capture_dashboard_output(self, incidents):
        dashboard = self.create_dashboard(incidents)

        output = StringIO()

        with redirect_stdout(output):
            dashboard.view_soc_dashboard()

        return output.getvalue()

    def test_dashboard_displays_incident_and_alert_totals(self):
        incidents = [
            self.create_incident(
                "HIGH",
                "OPEN",
                [
                    self.create_alert(
                        "Potential Brute Force",
                        "10.0.0.99"
                    ),
                    self.create_alert(
                        "Sensitive Data Detected",
                        "LOCAL_FILE"
                    )
                ]
            ),
            self.create_incident(
                "MEDIUM",
                "RESOLVED",
                [
                    self.create_alert(
                        "File Integrity Violation",
                        "LOCAL_FILE"
                    )
                ]
            )
        ]

        output = self.capture_dashboard_output(
            incidents
        )

        self.assertIn(
            "CYBERSHIELD SOC DASHBOARD",
            output
        )

        self.assertIn(
            "Total Incidents       : 2",
            output
        )

        self.assertIn(
            "Total Alerts          : 3",
            output
        )

    def test_dashboard_displays_status_counts(self):
        incidents = [
            self.create_incident(
                "HIGH",
                "OPEN",
                []
            ),
            self.create_incident(
                "HIGH",
                "OPEN",
                []
            ),
            self.create_incident(
                "MEDIUM",
                "INVESTIGATING",
                []
            ),
            self.create_incident(
                "LOW",
                "RESOLVED",
                []
            )
        ]

        output = self.capture_dashboard_output(
            incidents
        )

        self.assertIn(
            "OPEN                  : 2",
            output
        )

        self.assertIn(
            "INVESTIGATING         : 1",
            output
        )

        self.assertIn(
            "RESOLVED              : 1",
            output
        )

    def test_dashboard_displays_severity_counts(self):
        incidents = [
            self.create_incident(
                "CRITICAL",
                "OPEN",
                []
            ),
            self.create_incident(
                "HIGH",
                "OPEN",
                []
            ),
            self.create_incident(
                "HIGH",
                "RESOLVED",
                []
            ),
            self.create_incident(
                "MEDIUM",
                "OPEN",
                []
            ),
            self.create_incident(
                "LOW",
                "OPEN",
                []
            )
        ]

        output = self.capture_dashboard_output(
            incidents
        )

        self.assertIn(
            "CRITICAL              : 1",
            output
        )

        self.assertIn(
            "HIGH                  : 2",
            output
        )

        self.assertIn(
            "MEDIUM                : 1",
            output
        )

        self.assertIn(
            "LOW                   : 1",
            output
        )

    def test_dashboard_displays_top_threats(self):
        incidents = [
            self.create_incident(
                "HIGH",
                "OPEN",
                [
                    self.create_alert(
                        "Potential Brute Force",
                        "10.0.0.99"
                    ),
                    self.create_alert(
                        "Potential Brute Force",
                        "10.0.0.99"
                    ),
                    self.create_alert(
                        "Sensitive Data Detected",
                        "LOCAL_FILE"
                    )
                ]
            ),
            self.create_incident(
                "HIGH",
                "INVESTIGATING",
                [
                    self.create_alert(
                        "Potential Brute Force",
                        "10.0.0.99"
                    ),
                    self.create_alert(
                        "File Integrity Violation",
                        "LOCAL_FILE"
                    )
                ]
            )
        ]

        output = self.capture_dashboard_output(
            incidents
        )

        self.assertIn(
            "Potential Brute Force",
            output
        )

        self.assertIn(
            "Sensitive Data Detected",
            output
        )

        self.assertIn(
            "File Integrity Violation",
            output
        )

    def test_dashboard_displays_top_source_ips(self):
        incidents = [
            self.create_incident(
                "HIGH",
                "OPEN",
                [
                    self.create_alert(
                        "Potential Brute Force",
                        "10.0.0.99"
                    ),
                    self.create_alert(
                        "Potential Brute Force",
                        "10.0.0.99"
                    ),
                    self.create_alert(
                        "Sensitive Data Detected",
                        "LOCAL_FILE"
                    )
                ]
            ),
            self.create_incident(
                "HIGH",
                "OPEN",
                [
                    self.create_alert(
                        "Potential Brute Force",
                        "10.0.0.99"
                    ),
                    self.create_alert(
                        "File Integrity Violation",
                        "LOCAL_FILE"
                    )
                ]
            )
        ]

        output = self.capture_dashboard_output(
            incidents
        )

        self.assertIn(
            "10.0.0.99",
            output
        )

        self.assertIn(
            "LOCAL_FILE",
            output
        )

    def test_dashboard_handles_empty_incidents(self):
        output = self.capture_dashboard_output([])

        self.assertIn(
            "Total Incidents       : 0",
            output
        )

        self.assertIn(
            "Total Alerts          : 0",
            output
        )

        self.assertIn(
            "CRITICAL              : 0",
            output
        )

        self.assertIn(
            "HIGH                  : 0",
            output
        )

        self.assertIn(
            "MEDIUM                : 0",
            output
        )

        self.assertIn(
            "LOW                   : 0",
            output
        )

    def test_menu_routes_to_dashboard(self):
        dashboard = SOCDashboard.__new__(
            SOCDashboard
        )

        dashboard.display_menu = Mock()
        dashboard.view_soc_dashboard = Mock()

        with patch(
            "builtins.input",
            side_effect=[
                "11",
                "12"
            ]
        ):
            dashboard.start()

        dashboard.view_soc_dashboard.assert_called_once()


if __name__ == "__main__":
    unittest.main()
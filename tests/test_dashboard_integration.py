import unittest
from io import StringIO
from types import SimpleNamespace
from unittest.mock import patch

from main import SOCDashboard


class TestDashboardIntegration(unittest.TestCase):

    def create_incident(
        self,
        severity="HIGH",
        status="OPEN",
        alerts=None
    ):
        if alerts is None:
            alerts = []

        return SimpleNamespace(
            incident_id="INC-001",
            title="Test Incident",
            description="Test security incident",
            severity=severity,
            status=status,
            alerts=alerts
        )

    def create_alert(
        self,
        threat_type,
        source_ip=None
    ):
        return SimpleNamespace(
            threat_type=threat_type,
            source_ip=source_ip
        )

    # ------------------------------------------------------------
    # Dashboard overview
    # ------------------------------------------------------------

    @patch("main.SOCDashboard.get_incidents")
    def test_dashboard_displays_incident_overview(
        self,
        mock_get_incidents
    ):
        incidents = [
            self.create_incident(
                alerts=[
                    self.create_alert(
                        "Potential Brute Force",
                        "10.0.0.99"
                    )
                ]
            ),
            self.create_incident(
                severity="CRITICAL",
                status="INVESTIGATING",
                alerts=[
                    self.create_alert(
                        "Sensitive Data Detected",
                        "LOCAL_FILE"
                    )
                ]
            )
        ]

        mock_get_incidents.return_value = incidents

        dashboard = SOCDashboard()

        output = StringIO()

        with patch(
            "sys.stdout",
            new=output
        ):
            dashboard.view_soc_dashboard()

        result = output.getvalue()

        self.assertIn(
            "CYBERSHIELD SOC DASHBOARD",
            result
        )

        self.assertIn(
            "Total Incidents       : 2",
            result
        )

        self.assertIn(
            "Total Alerts          : 2",
            result
        )

    # ------------------------------------------------------------
    # Status
    # ------------------------------------------------------------

    @patch("main.SOCDashboard.get_incidents")
    def test_dashboard_displays_status_counts(
        self,
        mock_get_incidents
    ):
        incidents = [
            self.create_incident(
                status="OPEN"
            ),
            self.create_incident(
                status="OPEN"
            ),
            self.create_incident(
                status="INVESTIGATING"
            ),
            self.create_incident(
                status="RESOLVED"
            )
        ]

        mock_get_incidents.return_value = incidents

        dashboard = SOCDashboard()

        output = StringIO()

        with patch(
            "sys.stdout",
            new=output
        ):
            dashboard.view_soc_dashboard()

        result = output.getvalue()

        self.assertIn(
            "OPEN                  : 2",
            result
        )

        self.assertIn(
            "INVESTIGATING         : 1",
            result
        )

        self.assertIn(
            "RESOLVED              : 1",
            result
        )

    # ------------------------------------------------------------
    # Severity
    # ------------------------------------------------------------

    @patch("main.SOCDashboard.get_incidents")
    def test_dashboard_displays_severity_counts(
        self,
        mock_get_incidents
    ):
        incidents = [
            self.create_incident(
                severity="CRITICAL"
            ),
            self.create_incident(
                severity="HIGH"
            ),
            self.create_incident(
                severity="HIGH"
            ),
            self.create_incident(
                severity="MEDIUM"
            ),
            self.create_incident(
                severity="LOW"
            )
        ]

        mock_get_incidents.return_value = incidents

        dashboard = SOCDashboard()

        output = StringIO()

        with patch(
            "sys.stdout",
            new=output
        ):
            dashboard.view_soc_dashboard()

        result = output.getvalue()

        self.assertIn(
            "CRITICAL              : 1",
            result
        )

        self.assertIn(
            "HIGH                  : 2",
            result
        )

        self.assertIn(
            "MEDIUM                : 1",
            result
        )

        self.assertIn(
            "LOW                   : 1",
            result
        )

    # ------------------------------------------------------------
    # Threat types
    # ------------------------------------------------------------

    @patch("main.SOCDashboard.get_incidents")
    def test_dashboard_displays_top_threat_types(
        self,
        mock_get_incidents
    ):
        incidents = [
            self.create_incident(
                alerts=[
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
            )
        ]

        mock_get_incidents.return_value = incidents

        dashboard = SOCDashboard()

        output = StringIO()

        with patch(
            "sys.stdout",
            new=output
        ):
            dashboard.view_soc_dashboard()

        result = output.getvalue()

        self.assertIn(
            "Potential Brute Force",
            result
        )

        self.assertIn(
            "Sensitive Data Detected",
            result
        )

    # ------------------------------------------------------------
    # Source IPs
    # ------------------------------------------------------------

    @patch("main.SOCDashboard.get_incidents")
    def test_dashboard_displays_top_source_ips(
        self,
        mock_get_incidents
    ):
        incidents = [
            self.create_incident(
                alerts=[
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
            )
        ]

        mock_get_incidents.return_value = incidents

        dashboard = SOCDashboard()

        output = StringIO()

        with patch(
            "sys.stdout",
            new=output
        ):
            dashboard.view_soc_dashboard()

        result = output.getvalue()

        self.assertIn(
            "10.0.0.99",
            result
        )

        self.assertIn(
            "LOCAL_FILE",
            result
        )

    # ------------------------------------------------------------
    # Empty dashboard
    # ------------------------------------------------------------

    @patch("main.SOCDashboard.get_incidents")
    def test_dashboard_handles_empty_incidents(
        self,
        mock_get_incidents
    ):
        mock_get_incidents.return_value = []

        dashboard = SOCDashboard()

        output = StringIO()

        with patch(
            "sys.stdout",
            new=output
        ):
            dashboard.view_soc_dashboard()

        result = output.getvalue()

        self.assertIn(
            "CYBERSHIELD SOC DASHBOARD",
            result
        )

        self.assertIn(
            "Total Incidents       : 0",
            result
        )

        self.assertIn(
            "Total Alerts          : 0",
            result
        )

        self.assertIn(
            "No threat data available.",
            result
        )

        self.assertIn(
            "No source IP data available.",
            result
        )


if __name__ == "__main__":
    unittest.main()
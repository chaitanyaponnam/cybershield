import unittest
from unittest.mock import patch

from core.alert import Alert
from core.incident import Incident
from main import SOCDashboard


class TestRiskIntegration(unittest.TestCase):

    def setUp(self):
        self.dashboard = SOCDashboard()

        self.low_incident = Incident(
            "Low Priority Incident",
            "10.0.0.10"
        )

        self.high_incident = Incident(
            "Brute Force Incident",
            "10.0.0.20"
        )

        self.critical_incident = Incident(
            "Sensitive Data Incident",
            "10.0.0.30"
        )

        brute_force_alert = Alert(
            "Potential Brute Force",
            "HIGH",
            "10.0.0.20",
            "Multiple failed login attempts detected."
        )

        sensitive_data_alert = Alert(
            "Sensitive Data Detected",
            "CRITICAL",
            "10.0.0.30",
            "Sensitive data detected."
        )

        self.high_incident.add_alert(
            brute_force_alert
        )

        self.critical_incident.add_alert(
            sensitive_data_alert
        )

        self.high_incident.update_status(
            "INVESTIGATING"
        )

        self.dashboard.manager.incidents = {
            self.low_incident.incident_id:
                self.low_incident,

            self.high_incident.incident_id:
                self.high_incident,

            self.critical_incident.incident_id:
                self.critical_incident
        }

    def test_risk_priority_displays_incidents(self):
        with patch("builtins.print") as mock_print:
            self.dashboard.view_incident_risk()

        output = "\n".join(
            str(call)
            for call in mock_print.call_args_list
        )

        self.assertIn(
            self.low_incident.incident_id,
            output
        )

        self.assertIn(
            self.high_incident.incident_id,
            output
        )

        self.assertIn(
            self.critical_incident.incident_id,
            output
        )

    def test_highest_risk_incident_appears_first(self):
        with patch("builtins.print") as mock_print:
            self.dashboard.view_incident_risk()

        output = "\n".join(
            str(call)
            for call in mock_print.call_args_list
        )

        critical_position = output.find(
            self.critical_incident.incident_id
        )

        high_position = output.find(
            self.high_incident.incident_id
        )

        low_position = output.find(
            self.low_incident.incident_id
        )

        self.assertGreaterEqual(
            critical_position,
            0
        )

        self.assertGreaterEqual(
            high_position,
            0
        )

        self.assertGreaterEqual(
            low_position,
            0
        )

        self.assertLess(
            critical_position,
            high_position
        )

        self.assertLess(
            high_position,
            low_position
        )

    def test_risk_scores_are_displayed(self):
        with patch("builtins.print") as mock_print:
            self.dashboard.view_incident_risk()

        output = "\n".join(
            str(call)
            for call in mock_print.call_args_list
        )

        self.assertIn(
            "75",
            output
        )

        self.assertIn(
            "65",
            output
        )

        self.assertIn(
            "25",
            output
        )

    def test_risk_levels_are_displayed(self):
        with patch("builtins.print") as mock_print:
            self.dashboard.view_incident_risk()

        output = "\n".join(
            str(call)
            for call in mock_print.call_args_list
        )

        self.assertIn(
            "CRITICAL",
            output
        )

        self.assertIn(
            "HIGH",
            output
        )

        self.assertIn(
            "MEDIUM",
            output
        )

    def test_empty_incident_list(self):
        self.dashboard.manager.incidents = {}

        with patch("builtins.print") as mock_print:
            self.dashboard.view_incident_risk()

        output = "\n".join(
            str(call)
            for call in mock_print.call_args_list
        )

        self.assertIn(
            "No incidents available.",
            output
        )

    def test_risk_calculation_does_not_modify_incidents(self):
        original_values = {}

        for incident in self.dashboard.get_incidents():
            original_values[
                incident.incident_id
            ] = (
                incident.severity,
                incident.status,
                len(incident.alerts)
            )

        with patch("builtins.print"):
            self.dashboard.view_incident_risk()

        for incident in self.dashboard.get_incidents():
            original = original_values[
                incident.incident_id
            ]

            self.assertEqual(
                incident.severity,
                original[0]
            )

            self.assertEqual(
                incident.status,
                original[1]
            )

            self.assertEqual(
                len(incident.alerts),
                original[2]
            )


if __name__ == "__main__":
    unittest.main()
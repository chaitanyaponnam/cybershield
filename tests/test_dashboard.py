
import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import Mock

from core.alert import Alert
from core.incident import Incident
from main import SOCDashboard


class TestSOCDashboard(unittest.TestCase):

    @staticmethod
    def make_login_alert(event_ids=None):
        return Alert(
            "Potential Brute Force",
            "HIGH",
            "10.0.0.99",
            (
                "5 failed logins between "
                "2026-09-29T10:00:00 and "
                "2026-09-29T10:04:00"
            ),
            event_ids=event_ids
        )

    @staticmethod
    def make_incident(
        key,
        severity="HIGH",
        status="OPEN"
    ):
        incident = Incident(
            "Test Incident",
            key
        )

        incident.severity = severity
        incident.status = status

        return incident

    def test_empty_statistics(self):
        stats = (
            SOCDashboard.get_incident_statistics(
                []
            )
        )

        self.assertEqual(
            stats["total_incidents"],
            0
        )

        self.assertEqual(
            stats["unique_tracked_login_events"],
            0
        )

        self.assertEqual(
            stats["brute_force_incidents"],
            0
        )

    def test_severity_and_status_counts(self):
        first = self.make_incident(
            "INCIDENT:1",
            "HIGH",
            "INVESTIGATING"
        )

        second = self.make_incident(
            "INCIDENT:2",
            "CRITICAL",
            "OPEN"
        )

        third = self.make_incident(
            "INCIDENT:3",
            "HIGH",
            "RESOLVED"
        )

        stats = (
            SOCDashboard.get_incident_statistics(
                [first, second, third]
            )
        )

        self.assertEqual(
            stats["total_incidents"],
            3
        )

        self.assertEqual(
            stats["severity"]["HIGH"],
            2
        )

        self.assertEqual(
            stats["severity"]["CRITICAL"],
            1
        )

        self.assertEqual(
            stats["status"]["INVESTIGATING"],
            1
        )

        self.assertEqual(
            stats["status"]["OPEN"],
            1
        )

        self.assertEqual(
            stats["status"]["RESOLVED"],
            1
        )

    def test_unique_events_across_incidents(self):
        first = self.make_incident(
            "INCIDENT:1"
        )

        first.add_alert(
            self.make_login_alert(
                ["A", "B", "C", "D", "E"]
            )
        )

        second = self.make_incident(
            "INCIDENT:2"
        )

        second.add_alert(
            self.make_login_alert(
                ["C", "D", "E", "F", "G"]
            )
        )

        stats = (
            SOCDashboard.get_incident_statistics(
                [first, second]
            )
        )

        self.assertEqual(
            stats["unique_tracked_login_events"],
            7
        )

        self.assertEqual(
            stats["brute_force_incidents"],
            2
        )

    def test_legacy_events_not_counted_as_exact(self):
        incident = self.make_incident(
            "INCIDENT:LEGACY"
        )

        incident.add_alert(
            self.make_login_alert()
        )

        stats = (
            SOCDashboard.get_incident_statistics(
                [incident]
            )
        )

        self.assertEqual(
            stats["unique_tracked_login_events"],
            0
        )

        self.assertEqual(
            stats["legacy_login_alerts"],
            1
        )

    def test_statistics_display(self):
        incident = self.make_incident(
            "INCIDENT:1"
        )

        incident.add_alert(
            self.make_login_alert(
                ["A", "B", "C", "D", "E"]
            )
        )

        dashboard = SOCDashboard.__new__(
            SOCDashboard
        )

        dashboard.manager = Mock()
        dashboard.manager.incidents = {
            incident.correlation_key: incident
        }

        output = io.StringIO()

        with redirect_stdout(output):
            dashboard.view_statistics()

        text = output.getvalue()

        self.assertIn(
            "Total incidents: 1",
            text
        )

        self.assertIn(
            "HIGH: 1",
            text
        )

        self.assertIn(
            "Unique tracked failed-login events: 5",
            text
        )


if __name__ == "__main__":
    unittest.main()
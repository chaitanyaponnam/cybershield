
import unittest
from io import StringIO
from types import SimpleNamespace
from unittest.mock import patch

from main import SOCDashboard


class TestResponseCLI(unittest.TestCase):

    INCIDENT_ID = "test-incident-001"

    def setUp(self):
        self.dashboard = SOCDashboard()
        self.dashboard.get_incidents = lambda: [
            SimpleNamespace(incident_id=self.INCIDENT_ID)
        ]

    @patch("builtins.input")
    def test_acknowledge_action_is_recorded_for_existing_incident(
        self, mock_input
    ):
        mock_input.side_effect = [
            "1",
            self.INCIDENT_ID,
            "Chaitanya",
            "Reviewed suspicious login",
            "6",
        ]

        with patch("sys.stdout", new_callable=StringIO) as output:
            self.dashboard.incident_response_actions()

        history = self.dashboard.response_manager.get_history(
            self.INCIDENT_ID
        )

        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["action"], "ACKNOWLEDGE")
        self.assertEqual(history[0]["performed_by"], "Chaitanya")
        self.assertEqual(
            history[0]["details"],
            "Reviewed suspicious login",
        )
        self.assertIn(
            "Response action recorded successfully.",
            output.getvalue(),
        )

    @patch("builtins.input")
    def test_unknown_incident_does_not_record_action(self, mock_input):
        mock_input.side_effect = [
            "1",
            "unknown-incident",
            "6",
        ]

        with patch("sys.stdout", new_callable=StringIO) as output:
            self.dashboard.incident_response_actions()

        self.assertEqual(
            self.dashboard.response_manager.get_action_count(),
            0,
        )
        self.assertIn(
            "Incident not found. No action recorded.",
            output.getvalue(),
        )

    @patch("builtins.input")
    def test_response_history_is_displayed(self, mock_input):
        self.dashboard.response_manager.record_action(
            incident_id=self.INCIDENT_ID,
            action="ACKNOWLEDGE",
            performed_by="Chaitanya",
            details="Reviewed suspicious login",
        )

        mock_input.side_effect = [
            "5",
            self.INCIDENT_ID,
            "6",
        ]

        with patch("sys.stdout", new_callable=StringIO) as output:
            self.dashboard.incident_response_actions()

        displayed = output.getvalue()

        self.assertIn(self.INCIDENT_ID, displayed)
        self.assertIn("ACKNOWLEDGE", displayed)
        self.assertIn("Chaitanya", displayed)
        self.assertIn("Reviewed suspicious login", displayed)


if __name__ == "__main__":
    unittest.main()

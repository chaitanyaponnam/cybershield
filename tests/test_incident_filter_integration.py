import unittest
from unittest.mock import patch

from core.alert import Alert
from core.incident import Incident
from main import SOCDashboard


class TestIncidentFilterIntegration(unittest.TestCase):

    def setUp(self):
        self.dashboard = SOCDashboard()

        self.incident_1 = Incident(
            "Brute Force Attack",
            "10.0.0.10"
        )

        self.incident_2 = Incident(
            "Sensitive Data Exposure",
            "10.0.0.20"
        )

        self.alert_1 = Alert(
            "Potential Brute Force",
            "HIGH",
            "10.0.0.10",
            "Multiple failed login attempts detected."
        )

        self.alert_2 = Alert(
            "Sensitive Data Detected",
            "CRITICAL",
            "10.0.0.20",
            "Sensitive data detected."
        )

        self.incident_1.add_alert(
            self.alert_1
        )

        self.incident_2.add_alert(
            self.alert_2
        )

        self.incident_2.update_status(
            "INVESTIGATING"
        )

        self.dashboard.manager.incidents = {
            self.incident_1.incident_id:
                self.incident_1,
            self.incident_2.incident_id:
                self.incident_2
        }

    def test_search_menu_by_severity(self):
        with patch(
            "builtins.input",
            side_effect=[
                "1",
                "HIGH",
                "7"
            ]
        ):
            with patch(
                "builtins.print"
            ) as mock_print:

                self.dashboard.incident_search_and_filter()

        output = "\n".join(
            str(call)
            for call in mock_print.call_args_list
        )

        self.assertIn(
            self.incident_1.incident_id,
            output
        )

        self.assertNotIn(
            self.incident_2.incident_id,
            output
        )

    def test_search_menu_by_status(self):
        with patch(
            "builtins.input",
            side_effect=[
                "2",
                "INVESTIGATING",
                "7"
            ]
        ):
            with patch(
                "builtins.print"
            ) as mock_print:

                self.dashboard.incident_search_and_filter()

        output = "\n".join(
            str(call)
            for call in mock_print.call_args_list
        )

        self.assertIn(
            self.incident_2.incident_id,
            output
        )

    def test_search_menu_by_threat_type(self):
        with patch(
            "builtins.input",
            side_effect=[
                "3",
                "Potential Brute Force",
                "7"
            ]
        ):
            with patch(
                "builtins.print"
            ) as mock_print:

                self.dashboard.incident_search_and_filter()

        output = "\n".join(
            str(call)
            for call in mock_print.call_args_list
        )

        self.assertIn(
            self.incident_1.incident_id,
            output
        )

    def test_search_menu_by_source_ip(self):
        with patch(
            "builtins.input",
            side_effect=[
                "4",
                "10.0.0.20",
                "7"
            ]
        ):
            with patch(
                "builtins.print"
            ) as mock_print:

                self.dashboard.incident_search_and_filter()

        output = "\n".join(
            str(call)
            for call in mock_print.call_args_list
        )

        self.assertIn(
            self.incident_2.incident_id,
            output
        )

    def test_search_menu_by_incident_id(self):
        with patch(
            "builtins.input",
            side_effect=[
                "5",
                self.incident_1.incident_id,
                "7"
            ]
        ):
            with patch(
                "builtins.print"
            ) as mock_print:

                self.dashboard.incident_search_and_filter()

        output = "\n".join(
            str(call)
            for call in mock_print.call_args_list
        )

        self.assertIn(
            self.incident_1.incident_id,
            output
        )

    def test_search_menu_show_all(self):
        with patch(
            "builtins.input",
            side_effect=[
                "6",
                "7"
            ]
        ):
            with patch(
                "builtins.print"
            ) as mock_print:

                self.dashboard.incident_search_and_filter()

        output = "\n".join(
            str(call)
            for call in mock_print.call_args_list
        )

        self.assertIn(
            self.incident_1.incident_id,
            output
        )

        self.assertIn(
            self.incident_2.incident_id,
            output
        )

    def test_search_menu_no_match(self):
        with patch(
            "builtins.input",
            side_effect=[
                "1",
                "LOW",
                "7"
            ]
        ):
            with patch(
                "builtins.print"
            ) as mock_print:

                self.dashboard.incident_search_and_filter()

        output = "\n".join(
            str(call)
            for call in mock_print.call_args_list
        )

        self.assertIn(
            "No matching incidents found.",
            output
        )

    def test_search_menu_back(self):
        with patch(
            "builtins.input",
            side_effect=["7"]
        ):
            with patch(
                "builtins.print"
            ) as mock_print:

                self.dashboard.incident_search_and_filter()

        self.assertTrue(
            mock_print.called
        )


if __name__ == "__main__":
    unittest.main()

import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from main import SOCDashboard
from services.event_timeline import EventTimeline


class TestTimelineIntegration(unittest.TestCase):

    def setUp(self):
        self.dashboard = SOCDashboard.__new__(
            SOCDashboard
        )

    def test_view_all_events(self):
        events = [{
            "event_id": "A",
            "ip": "10.0.0.99",
            "username": "admin",
            "status": "FAILED",
            "timestamp": "2026-09-29T10:00:00"
        }]

        output = io.StringIO()

        with (
            patch(
                "builtins.input",
                return_value="1"
            ),
            patch.object(
                EventTimeline,
                "search",
                return_value=events
            ) as search,
            redirect_stdout(output)
        ):
            self.dashboard.view_event_timeline()

        search.assert_called_once_with()

        self.assertIn(
            "SOC EVENT TIMELINE",
            output.getvalue()
        )

        self.assertIn(
            "10.0.0.99",
            output.getvalue()
        )

    def test_filter_menu(self):
        answers = [
            "2",
            "10.0.0.99",
            "FAILED",
            "",
            ""
        ]

        with (
            patch(
                "builtins.input",
                side_effect=answers
            ),
            patch.object(
                EventTimeline,
                "search",
                return_value=[]
            ) as search,
            redirect_stdout(io.StringIO())
        ):
            self.dashboard.view_event_timeline()

        search.assert_called_once_with(
            source_ip="10.0.0.99",
            status="FAILED",
            start_time=None,
            end_time=None
        )

    def test_cancel_does_not_search(self):
        with (
            patch(
                "builtins.input",
                return_value="3"
            ),
            patch.object(
                EventTimeline,
                "search"
            ) as search,
            redirect_stdout(io.StringIO())
        ):
            self.dashboard.view_event_timeline()

        search.assert_not_called()

    def test_mixed_timezones_sort_correctly(self):
        events = [
            {
                "event_id": "LATER",
                "ip": "10.0.0.1",
                "status": "FAILED",
                "timestamp": (
                    "2026-09-29T12:00:00+05:30"
                )
            },
            {
                "event_id": "EARLIER",
                "ip": "10.0.0.2",
                "status": "FAILED",
                "timestamp": (
                    "2026-09-29T06:00:00Z"
                )
            }
        ]

        with patch(
            "services.event_timeline."
            "LogHistory.load_events",
            return_value=events
        ):
            results = EventTimeline.search()

        self.assertEqual(
            [
                event["event_id"]
                for event in results
            ],
            ["EARLIER", "LATER"]
        )


if __name__ == "__main__":
    unittest.main()
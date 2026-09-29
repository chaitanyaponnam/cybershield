
import unittest

from detectors.login_detector import LoginDetector
from services.log_generator import LogGenerator


class TestLogGenerator(unittest.TestCase):

    def test_every_event_has_unique_id(self):
        events = LogGenerator.generate_logs()

        self.assertEqual(len(events), 28)

        event_ids = [
            event["event_id"]
            for event in events
        ]

        self.assertEqual(
            len(event_ids),
            len(set(event_ids))
        )

    def test_brute_force_events_are_tracked(self):
        events = LogGenerator.generate_logs()

        detector = LoginDetector()
        alerts = detector.detect(events)

        attack_alerts = [
            alert
            for alert in alerts
            if alert.source_ip == "10.0.0.99"
        ]

        self.assertEqual(len(attack_alerts), 1)
        self.assertEqual(
            len(attack_alerts[0].event_ids),
            8
        )

    def test_identical_login_details_have_distinct_ids(self):
        events = LogGenerator.generate_logs()

        first = events[20]
        second = events[21]

        # Simulate two separate attempts with
        # identical timestamps and login details.
        second["timestamp"] = first["timestamp"]

        self.assertEqual(
            first["username"],
            second["username"]
        )
        self.assertEqual(
            first["timestamp"],
            second["timestamp"]
        )
        self.assertNotEqual(
            first["event_id"],
            second["event_id"]
        )

        detector = LoginDetector()
        alerts = detector.detect(events)

        attack_alert = next(
            alert
            for alert in alerts
            if alert.source_ip == "10.0.0.99"
        )

        self.assertEqual(
            len(attack_alert.event_ids),
            8
        )


if __name__ == "__main__":
    unittest.main()
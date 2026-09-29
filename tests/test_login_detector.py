
import unittest
from datetime import datetime, timedelta

from detectors.login_detector import LoginDetector


class TestLoginDetector(unittest.TestCase):

    def setUp(self):
        self.detector = LoginDetector(
            threshold=5,
            window_minutes=5
        )

        self.start_time = datetime(
            2026, 9, 29, 10, 0, 0
        )

    def create_event(
        self,
        ip,
        status,
        minutes=0
    ):
        timestamp = (
            self.start_time
            + timedelta(minutes=minutes)
        )

        return {
            "ip": ip,
            "status": status,
            "timestamp": timestamp.isoformat()
        }

    def test_brute_force_detection(self):
        events = [
            self.create_event(
                "10.0.0.99",
                "FAILED",
                minutes=i
            )
            for i in range(5)
        ]

        alerts = self.detector.detect(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(
            alerts[0].source_ip,
            "10.0.0.99"
        )
        self.assertEqual(
            alerts[0].severity,
            "HIGH"
        )

    def test_normal_login_activity(self):
        events = [
            self.create_event(
                "10.0.0.10",
                "SUCCESS",
                minutes=i
            )
            for i in range(10)
        ]

        self.assertEqual(
            self.detector.detect(events),
            []
        )

    def test_below_threshold(self):
        events = [
            self.create_event(
                "10.0.0.99",
                "FAILED",
                minutes=i
            )
            for i in range(4)
        ]

        self.assertEqual(
            self.detector.detect(events),
            []
        )

    def test_failures_outside_window(self):
        events = [
            self.create_event(
                "10.0.0.99",
                "FAILED",
                minutes=i * 10
            )
            for i in range(5)
        ]

        self.assertEqual(
            self.detector.detect(events),
            []
        )

    def test_separate_source_ips(self):
        events = []

        for ip in ["10.0.0.10", "10.0.0.20"]:
            events.extend([
                self.create_event(
                    ip,
                    "FAILED",
                    minutes=i
                )
                for i in range(5)
            ])

        alerts = self.detector.detect(events)

        self.assertEqual(len(alerts), 2)

        detected_ips = {
            alert.source_ip
            for alert in alerts
        }

        self.assertEqual(
            detected_ips,
            {"10.0.0.10", "10.0.0.20"}
        )

    def test_disabled_detector(self):
        self.detector.disable()

        events = [
            self.create_event(
                "10.0.0.99",
                "FAILED",
                minutes=i
            )
            for i in range(8)
        ]

        self.assertEqual(
            self.detector.detect(events),
            []
        )
    
    def test_alert_contains_attack_window(self):
        events = [
            self.create_event(
                "10.0.0.99",
                "FAILED",
                minutes=i
            )
            for i in range(5)
        ]

        alerts = self.detector.detect(events)

        self.assertEqual(len(alerts), 1)
        self.assertIn(
            "2026-09-29T10:00:00",
            alerts[0].description
        )
        self.assertIn(
            "2026-09-29T10:04:00",
            alerts[0].description
        )

    def test_separate_attacks_have_distinct_descriptions(self):
        first_attack = [
            self.create_event(
                "10.0.0.99",
                "FAILED",
                minutes=i
            )
            for i in range(5)
        ]

        second_attack = [
            self.create_event(
                "10.0.0.99",
                "FAILED",
                minutes=60 + i
            )
            for i in range(5)
        ]

        first_alert = self.detector.detect(
            first_attack
        )[0]

        second_alert = self.detector.detect(
            second_attack
        )[0]

        self.assertNotEqual(
            first_alert.description,
            second_alert.description
        )


if __name__ == "__main__":
    unittest.main()
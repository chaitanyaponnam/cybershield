
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.alert import Alert
from core.incident_manager import IncidentManager
from services.file_manager import FileManager


class TestIncidentManager(unittest.TestCase):

    def setUp(self):
        # Isolate tests from real project data.
        self.temp_dir = tempfile.TemporaryDirectory()

        self.data_patch = patch.object(
            FileManager,
            "DATA_DIR",
            Path(self.temp_dir.name)
        )
        self.data_patch.start()

        self.manager = IncidentManager()

        self.login_alert = Alert(
            "Potential Brute Force",
            "HIGH",
            "10.0.0.99",
            "5 failed logins within 5 minutes"
        )

        self.dlp_alert = Alert(
            "Sensitive Data Detected",
            "MEDIUM",
            "LOCAL_FILE",
            "Email detected in confidential.txt",
            affected_file="confidential.txt"
        )

        self.integrity_alert = Alert(
            "File Integrity Violation",
            "HIGH",
            "LOCAL_FILE",
            "File modified: confidential.txt",
            affected_file="confidential.txt"
        )

    def tearDown(self):
        self.data_patch.stop()
        self.temp_dir.cleanup()

    def test_incident_correlation(self):
        alerts = [
            self.login_alert,
            self.dlp_alert,
            self.integrity_alert
        ]

        incidents = self.manager.correlate(alerts)

        self.assertEqual(len(incidents), 2)

        file_incident = self.manager.incidents[
            "FILE:confidential.txt"
        ]

        self.assertEqual(
            len(file_incident.alerts),
            2
        )

        self.assertEqual(
            file_incident.severity,
            "HIGH"
        )

    def test_duplicate_prevention(self):
        self.manager.correlate([self.login_alert])

        # Same finding, but with a new alert ID.
        duplicate = Alert(
            "Potential Brute Force",
            "HIGH",
            "10.0.0.99",
            "5 failed logins within 5 minutes"
        )

        self.manager.correlate([duplicate])

        incident = self.manager.incidents[
            "IP:10.0.0.99"
        ]

        self.assertEqual(
            len(incident.alerts),
            1
        )

    def test_incident_persistence(self):
        self.manager.correlate([self.login_alert])

        incident = self.manager.incidents[
            "IP:10.0.0.99"
        ]

        incident.update_status("INVESTIGATING")
        incident.add_note(
            "Chaitanya",
            "Reviewing simulated login activity."
        )

        self.manager.save_incidents()

        # Simulate restarting the application.
        reloaded_manager = IncidentManager()

        restored = reloaded_manager.incidents[
            "IP:10.0.0.99"
        ]

        self.assertEqual(
            restored.incident_id,
            incident.incident_id
        )

        self.assertEqual(
            restored.status,
            "INVESTIGATING"
        )

        self.assertEqual(
            len(restored.notes),
            1
        )
    
    def test_separate_attack_windows(self):
        from detectors.login_detector import LoginDetector

        detector = LoginDetector(
            threshold=5,
            window_minutes=5
        )

        def create_attack(start_hour):
            return [
                {
                    "ip": "10.0.0.99",
                    "status": "FAILED",
                    "timestamp": (
                        f"2026-09-29T{start_hour:02d}:"
                        f"{minute:02d}:00"
                    )
                }
                for minute in range(5)
            ]

        first_alert = detector.detect(
            create_attack(10)
        )[0]

        second_alert = detector.detect(
            create_attack(11)
        )[0]

        manager = IncidentManager()

        manager.correlate([first_alert])
        manager.correlate([second_alert])

        incident = manager.incidents[
            "IP:10.0.0.99"
        ]

        self.assertEqual(
            len(incident.alerts),
            2
        )

        # Reprocessing the same attack must not
        # create another alert.
        manager.correlate([first_alert])

        self.assertEqual(
            len(incident.alerts),
            2
        )


if __name__ == "__main__":
    unittest.main()

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.alert import Alert
from core.incident_manager import IncidentManager
from detectors.login_detector import LoginDetector
from services.file_manager import FileManager


class TestIncidentManager(unittest.TestCase):

    def setUp(self):
        # Keep tests separate from real project data.
        self.temp_dir = tempfile.TemporaryDirectory()

        self.data_patch = patch.object(
            FileManager,
            "DATA_DIR",
            Path(self.temp_dir.name)
        )
        self.data_patch.start()

        self.manager = IncidentManager()

        # Legacy alert without an attack window.
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
        self.manager.correlate([
            self.login_alert
        ])

        # Same finding with a different alert ID.
        duplicate = Alert(
            "Potential Brute Force",
            "HIGH",
            "10.0.0.99",
            "5 failed logins within 5 minutes"
        )

        self.manager.correlate([
            duplicate
        ])

        incident = self.manager.incidents[
            "IP:10.0.0.99"
        ]

        self.assertEqual(
            len(incident.alerts),
            1
        )

    def test_incident_persistence(self):
        self.manager.correlate([
            self.login_alert
        ])

        incident = self.manager.incidents[
            "IP:10.0.0.99"
        ]

        incident.update_status(
            "INVESTIGATING"
        )

        incident.add_note(
            "Chaitanya",
            "Reviewing simulated login activity."
        )

        self.manager.save_incidents()

        # Simulate restarting CyberShield.
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
        detector = LoginDetector(
            threshold=5,
            window_minutes=5
        )

        def create_attack(hour):
            return [
                {
                    "ip": "10.0.0.99",
                    "status": "FAILED",
                    "timestamp": (
                        f"2026-09-29T{hour:02d}:"
                        f"{minute:02d}:00"
                    )
                }
                for minute in range(5)
            ]

        # Two separate attacks from the same IP.
        first_alert = detector.detect(
            create_attack(10)
        )[0]

        second_alert = detector.detect(
            create_attack(11)
        )[0]

        self.manager.correlate([
            first_alert
        ])

        self.manager.correlate([
            second_alert
        ])

        # Different attack windows create
        # separate incidents.
        self.assertEqual(
            len(self.manager.incidents),
            2
        )

        incidents = list(
            self.manager.incidents.values()
        )

        self.assertNotEqual(
            incidents[0].incident_id,
            incidents[1].incident_id
        )

        self.assertTrue(
            all(
                len(incident.alerts) == 1
                for incident in incidents
            )
        )

        # Reprocessing the same attacks must
        # not create duplicate incidents.
        self.manager.correlate([
            first_alert,
            second_alert
        ])

        self.assertEqual(
            len(self.manager.incidents),
            2
        )

    def test_legacy_incident_compatibility(self):
        # Create an incident using the old
        # IP-based correlation format.
        self.manager.correlate([
            self.login_alert
        ])

        original = self.manager.incidents[
            "IP:10.0.0.99"
        ]

        original.update_status(
            "INVESTIGATING"
        )

        original.add_note(
            "Chaitanya",
            "Existing investigation must be preserved."
        )

        original_id = original.incident_id

        self.manager.save_incidents()

        # Reload the saved incident.
        reloaded_manager = IncidentManager()

        restored = reloaded_manager.incidents[
            "IP:10.0.0.99"
        ]

        self.assertEqual(
            restored.incident_id,
            original_id
        )

        self.assertEqual(
            restored.status,
            "INVESTIGATING"
        )

        self.assertEqual(
            len(restored.notes),
            1
        )

        # The original alert must not be
        # duplicated after reloading.
        reloaded_manager.correlate([
            self.login_alert
        ])

        self.assertEqual(
            len(restored.alerts),
            1
        )


if __name__ == "__main__":
    unittest.main()

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.alert import Alert
from core.incident_manager import IncidentManager
from services.file_manager import FileManager


class TestIncidentPersistence(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

        self.data_patch = patch.object(
            FileManager,
            "DATA_DIR",
            Path(self.temp_dir.name)
        )
        self.data_patch.start()

        self.manager = IncidentManager()

        self.alert = Alert(
            "Potential Brute Force",
            "HIGH",
            "192.0.2.10",
            "5 failed logins within 5 minutes"
        )

    def tearDown(self):
        self.data_patch.stop()
        self.temp_dir.cleanup()

    def test_empty_store_loads_without_incidents(self):
        self.assertEqual(
            self.manager.incidents,
            {}
        )

    def test_saved_incident_survives_restart(self):
        incidents = self.manager.correlate([
            self.alert
        ])
        self.manager.save_incidents()

        original = incidents[0]

        reloaded_manager = IncidentManager()

        restored = next(
            incident
            for incident in reloaded_manager.incidents.values()
            if incident.incident_id == original.incident_id
        )

        self.assertEqual(
            restored.incident_id,
            original.incident_id
        )
        self.assertEqual(
            restored.title,
            original.title
        )
        self.assertEqual(
            restored.severity,
            original.severity
        )

    def test_updated_status_survives_restart(self):
        incidents = self.manager.correlate([
            self.alert
        ])
        incident = incidents[0]

        self.assertTrue(
            self.manager.update_incident(
                incident.incident_id,
                "INVESTIGATING"
            )
        )

        reloaded_manager = IncidentManager()

        restored = next(
            item
            for item in reloaded_manager.incidents.values()
            if item.incident_id == incident.incident_id
        )

        self.assertEqual(
            restored.status,
            "INVESTIGATING"
        )

    def test_unknown_incident_cannot_be_updated(self):
        self.assertFalse(
            self.manager.update_incident(
                "unknown-incident",
                "INVESTIGATING"
            )
        )


if __name__ == "__main__":
    unittest.main()

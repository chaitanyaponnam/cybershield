
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from detectors.dlp_detector import DLPDetector
from detectors.integrity_detector import IntegrityDetector
from services.file_manager import FileManager


class TestDLPDetector(unittest.TestCase):

    def setUp(self):
        self.detector = DLPDetector()

    def test_sensitive_data_detection(self):
        events = [{
            "filename": "sample.txt",
            "content": (
                "Email: demo@example.com\n"
                "Phone: 9876543210\n"
                "Account: ACC-12345678"
            )
        }]

        alerts = self.detector.detect(events)

        self.assertEqual(len(alerts), 3)
        self.assertTrue(
            all(
                alert.affected_file == "sample.txt"
                for alert in alerts
            )
        )

    def test_clean_document(self):
        events = [{
            "filename": "clean.txt",
            "content": "This is an ordinary test document."
        }]

        alerts = self.detector.detect(events)

        self.assertEqual(len(alerts), 0)

    def test_disabled_detector(self):
        self.detector.disable()

        events = [{
            "filename": "sample.txt",
            "content": "demo@example.com"
        }]

        self.assertEqual(
            self.detector.detect(events),
            []
        )


class TestIntegrityDetector(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp_dir.name)

        self.data_patch = patch.object(
            FileManager,
            "DATA_DIR",
            self.directory
        )
        self.data_patch.start()

        self.test_file = self.directory / "sample.txt"
        self.test_file.write_text(
            "Original content",
            encoding="utf-8"
        )

        self.detector = IntegrityDetector()

    def tearDown(self):
        self.data_patch.stop()
        self.temp_dir.cleanup()

    def test_unchanged_file(self):
        self.detector.create_baseline([
            self.test_file
        ])

        alerts = self.detector.detect([
            self.test_file
        ])

        self.assertEqual(len(alerts), 0)

    def test_modified_file(self):
        self.detector.create_baseline([
            self.test_file
        ])

        self.test_file.write_text(
            "Modified content",
            encoding="utf-8"
        )

        alerts = self.detector.detect([
            self.test_file
        ])

        self.assertEqual(len(alerts), 1)
        self.assertEqual(
            alerts[0].severity,
            "HIGH"
        )

    def test_deleted_file(self):
        self.detector.create_baseline([
            self.test_file
        ])

        self.test_file.unlink()

        alerts = self.detector.detect([
            self.test_file
        ])

        self.assertEqual(len(alerts), 1)
        self.assertIn(
            "missing",
            alerts[0].description.lower()
        )


if __name__ == "__main__":
    unittest.main()
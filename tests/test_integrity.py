
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from detectors.integrity_detector import IntegrityDetector
from services.file_manager import FileManager


class TestIntegrityDetector(unittest.TestCase):

    def setUp(self):
        self.temp_dir = TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        self.test_file = (
            Path(self.temp_dir.name) / "confidential.txt"
        )

        self.test_file.write_text(
            "Original confidential content",
            encoding="utf-8"
        )

        self.detector = IntegrityDetector()
        self.files = [str(self.test_file)]

        # Isolate baseline storage from real project data.
        self.baseline = {}

        self.load_patcher = patch.object(
            FileManager,
            "load_data",
            side_effect=self.load_baseline
        )

        self.save_patcher = patch.object(
            FileManager,
            "save_data",
            side_effect=self.save_baseline
        )

        self.load_patcher.start()
        self.save_patcher.start()

        self.addCleanup(self.load_patcher.stop)
        self.addCleanup(self.save_patcher.stop)

    def load_baseline(self, filename):
        if filename == "file_hashes.json":
            return self.baseline.copy()

        raise AssertionError(
            f"Unexpected file read: {filename}"
        )

    def save_baseline(self, filename, data):
        if filename != "file_hashes.json":
            raise AssertionError(
                f"Unexpected file write: {filename}"
            )

        self.baseline = data.copy()

    def test_baseline_creation(self):
        self.detector.create_baseline(self.files)

        resolved_path = str(
            self.test_file.resolve()
        )

        self.assertIn(
            resolved_path,
            self.baseline
        )

        self.assertEqual(
            self.baseline[resolved_path],
            self.detector.calculate_hash(
                self.test_file
            )
        )

    def test_unchanged_file_has_no_alerts(self):
        self.detector.create_baseline(self.files)

        alerts = self.detector.detect(self.files)

        self.assertEqual(alerts, [])

    def test_modified_file_triggers_alert(self):
        self.detector.create_baseline(self.files)

        self.test_file.write_text(
            "Modified confidential content",
            encoding="utf-8"
        )

        alerts = self.detector.detect(self.files)

        self.assertEqual(len(alerts), 1)

        self.assertEqual(
            alerts[0].threat_type,
            "File Integrity Violation"
        )

        self.assertEqual(
            alerts[0].severity,
            "HIGH"
        )

        self.assertEqual(
            alerts[0].affected_file,
            "confidential.txt"
        )


if __name__ == "__main__":
    unittest.main()